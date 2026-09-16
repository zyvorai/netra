import { useEffect, useMemo, useRef, useState } from 'react';
import { api, wsURL } from '../api';
import CaptureHistory from '../components/CaptureHistory';
import { decodeL3L4, hexDump } from '../lib/packetDecode';

type CaptureSpec = {
  node: string;
  backend?: string;
  protocol?: string;
  host?: string;
  port?: number;
  snapLen?: number;
  maxPps?: number;
  requestor?: string;
  startedAt?: string;
  expiresAt?: string;
};
type CaptureStatus = { active?: CaptureSpec[] };
type BulkResult = { node: string; ok: boolean; error?: string };

type Frame = { observedAtUnixNano: bigint; origLen: number; direction: number; family: number; protocol: number; data: Uint8Array<ArrayBuffer> };

const FRAME_HEADER_LEN = 20;
const PROTOCOL_NAMES: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };
const MAX_LIVE_ROWS = 500;

// decodeFrame mirrors internal/capture.DecodeFrame's wire format exactly —
// see that Go file's own doc comment for the byte layout both ends agree
// on (all integers little-endian).
function decodeFrame(buf: ArrayBuffer): Frame {
  const dv = new DataView(buf);
  return {
    observedAtUnixNano: dv.getBigInt64(0, true),
    origLen: dv.getUint32(8, true),
    direction: dv.getUint8(16),
    family: dv.getUint8(17),
    protocol: dv.getUint8(18),
    data: new Uint8Array(buf, FRAME_HEADER_LEN, dv.getUint32(12, true)),
  };
}

// buildPCAP assembles a classic (non-pcapng) libpcap file client-side from
// every frame received this session — mirrors internal/capture's
// WritePCAPHeader/WritePCAPRecord byte-for-byte, so the download opens
// directly in Wireshark with no server-side capture storage or export
// endpoint needed.
function buildPCAP(frames: Frame[]): Blob {
  const parts: BlobPart[] = [];
  const hdr = new DataView(new ArrayBuffer(24));
  hdr.setUint32(0, 0xa1b2c3d4, true);
  hdr.setUint16(4, 2, true);
  hdr.setUint16(6, 4, true);
  hdr.setUint32(16, 9000, true);
  hdr.setUint32(20, 1, true); // LINKTYPE_ETHERNET
  parts.push(hdr.buffer);
  for (const f of frames) {
    const rec = new DataView(new ArrayBuffer(16));
    const nanos = f.observedAtUnixNano;
    rec.setUint32(0, Number(nanos / 1_000_000_000n), true);
    rec.setUint32(4, Number((nanos % 1_000_000_000n) / 1000n), true);
    rec.setUint32(8, f.data.byteLength, true);
    rec.setUint32(12, f.origLen, true);
    parts.push(rec.buffer, f.data);
  }
  return new Blob(parts, { type: 'application/vnd.tcpdump.pcap' });
}

export default function Capture() {
  const [status, setStatus] = useState<CaptureStatus>();
  const [nodes, setNodes] = useState<string[]>([]);
  const [nodeToAdd, setNodeToAdd] = useState('');
  const [selectedNodes, setSelectedNodes] = useState<string[]>([]);
  const [backend, setBackend] = useState('');
  const [protocol, setProtocol] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [duration, setDuration] = useState('60s');
  const [err, setErr] = useState('');
  const [live, setLive] = useState(false);
  const [watching, setWatching] = useState('');
  const [rows, setRows] = useState<Frame[]>([]);
  const [filterProtocol, setFilterProtocol] = useState('');
  const [filterDirection, setFilterDirection] = useState('');
  const [filterQuery, setFilterQuery] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const framesRef = useRef<Frame[]>([]);

  const loadStatus = () => api<CaptureStatus>('/api/v1/capture/status').then(setStatus).catch((e) => setErr(String(e)));
  useEffect(() => {
    loadStatus();
    const t = setInterval(loadStatus, 5000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    api<{ nodes?: { node?: string }[] }>('/api/v1/fleet')
      .then((inv) => setNodes((inv.nodes || []).map((n) => n.node || '').filter(Boolean)))
      .catch(() => {});
  }, []);
  useEffect(() => () => wsRef.current?.close(), []);

  function addNode() {
    if (nodeToAdd && !selectedNodes.includes(nodeToAdd)) setSelectedNodes((prev) => [...prev, nodeToAdd]);
    setNodeToAdd('');
  }
  function removeNode(n: string) {
    setSelectedNodes((prev) => prev.filter((x) => x !== n));
  }

  function watch(target: string) {
    wsRef.current?.close();
    framesRef.current = [];
    setRows([]);
    setErr('');
    setExpanded(null);
    setWatching(target);
    const ws = new WebSocket(wsURL(`/api/v1/vms/${encodeURIComponent(target)}/capture/ws`));
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => setLive(true);
    ws.onmessage = (ev) => {
      const f = decodeFrame(ev.data as ArrayBuffer);
      framesRef.current.push(f);
      setRows((prev) => [...prev.slice(-(MAX_LIVE_ROWS - 1)), f]);
    };
    ws.onerror = () => setErr('WebSocket error');
    ws.onclose = () => setLive(false);
    wsRef.current = ws;
  }

  async function start() {
    if (selectedNodes.length === 0) { setErr('at least one node is required'); return; }
    if (!protocol && !host && !port) { setErr('at least one of protocol, host, or port is required'); return; }
    const body: Record<string, unknown> = {};
    if (backend) body.backend = backend;
    if (protocol) body.protocol = protocol;
    if (host) body.host = host;
    if (port) body.port = Number(port);
    const m = /^(\d+)([smh])$/.exec(duration.trim());
    if (m) body.durationSeconds = Number(m[1]) * { s: 1, m: 60, h: 3600 }[m[2] as 's' | 'm' | 'h'];
    try {
      if (selectedNodes.length === 1) {
        await api(`/api/v1/vms/${encodeURIComponent(selectedNodes[0])}/capture`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        setErr('');
        await loadStatus();
        watch(selectedNodes[0]);
      } else {
        const res = await api<{ results?: BulkResult[] }>('/api/v1/capture/bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nodes: selectedNodes, ...body }) });
        const results = res.results || [];
        const failed = results.filter((r) => !r.ok);
        setErr(failed.length ? `${failed.length} of ${selectedNodes.length} node(s) failed to start: ${failed.map((f) => `${f.node} (${f.error})`).join('; ')}` : '');
        await loadStatus();
        const firstOK = results.find((r) => r.ok);
        if (firstOK) watch(firstOK.node);
      }
    } catch (e) { setErr(String(e)); }
  }

  async function stop(target: string) {
    try {
      await api(`/api/v1/vms/${encodeURIComponent(target)}/capture`, { method: 'DELETE' });
      await loadStatus();
      if (target === watching) { wsRef.current?.close(); }
    } catch (e) { setErr(String(e)); }
  }

  function download() {
    const blob = buildPCAP(framesRef.current);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netra-capture-${watching || 'session'}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function repeat(e: { node: string; backend?: string; protocol?: string; host?: string; port?: number }) {
    setSelectedNodes([e.node]);
    setBackend(e.backend || '');
    setProtocol(e.protocol || '');
    setHost(e.host || '');
    setPort(e.port ? String(e.port) : '');
  }

  const active = status?.active || [];
  const decoded = useMemo(() => rows.map((f) => decodeL3L4(f.data)), [rows]);
  const filteredIdx = useMemo(() => {
    const q = filterQuery.trim().toLowerCase();
    return rows
      .map((_, i) => i)
      .filter((i) => {
        const f = rows[i];
        if (filterProtocol && (PROTOCOL_NAMES[f.protocol] || String(f.protocol)) !== filterProtocol) return false;
        if (filterDirection && String(f.direction) !== filterDirection) return false;
        if (q) {
          const hay = `${decoded[i]?.summary || ''} ${PROTOCOL_NAMES[f.protocol] || ''}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      });
  }, [rows, decoded, filterProtocol, filterDirection, filterQuery]);

  return (
    <div className="grid">
      {err && <section className="card span3"><p className="warning">{err}</p></section>}
      {active.length > 0 && (
        <section className="card span3">
          <p className="warning">Capturing full packet bytes on {active.length} node{active.length === 1 ? '' : 's'} — captured traffic may contain sensitive application data (auth headers, tokens, cookies).</p>
        </section>
      )}

      <section className="card span3">
        <p className="eyebrow">PACKET CAPTURE</p>
        <h3>Start a capture</h3>
        <p>
          Full packet bytes by default, filtered and time-bounded (max 5 minutes).{' '}
          {backend === 'afpacket'
            ? 'AF_PACKET mode: a pure userspace raw-socket capture, no eBPF object dependency.'
            : 'Standalone, fail-open eBPF observer — never affects the datapath verdict.'}{' '}
          Add more than one node to start a bulk capture across all of them at once.
        </p>
        <div className="toolbar">
          <label>
            Node{' '}
            {nodes.length > 0 ? (
              <select value={nodeToAdd} onChange={(e) => setNodeToAdd(e.target.value)}>
                <option value="">select…</option>
                {nodes.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            ) : (
              <input value={nodeToAdd} onChange={(e) => setNodeToAdd(e.target.value)} placeholder="node-1" />
            )}
          </label>
          <button className="btn-secondary" onClick={addNode} disabled={!nodeToAdd}>Add node</button>
          <label>
            Backend{' '}
            <select value={backend} onChange={(e) => setBackend(e.target.value)}>
              <option value="">eBPF (default)</option>
              <option value="afpacket">AF_PACKET</option>
            </select>
          </label>
          <label>
            Protocol{' '}
            <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
              <option value="">any</option>
              <option value="tcp">tcp</option>
              <option value="udp">udp</option>
              <option value="icmp">icmp</option>
              <option value="icmpv6">icmpv6</option>
            </select>
          </label>
          <label>Host <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.5" /></label>
          <label>Port <input value={port} onChange={(e) => setPort(e.target.value)} placeholder="443" /></label>
          <label>Duration <input value={duration} onChange={(e) => setDuration(e.target.value)} placeholder="60s" /></label>
          <button className="primary" onClick={start}>Start capture{selectedNodes.length > 1 ? ` (${selectedNodes.length} nodes)` : ''}</button>
        </div>
        <div className="chips">
          {selectedNodes.length === 0 && <span>No nodes selected yet.</span>}
          {selectedNodes.map((n) => <button key={n} aria-label={`Remove ${n}`} onClick={() => removeNode(n)}>{n} ×</button>)}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">ACTIVE SESSIONS</p>
        <h3>{active.length} active</h3>
        <div className="list">
          {active.length === 0 && <p className="empty-state">No capture sessions running.</p>}
          {active.map((c) => (
            <div className="agent wide" key={c.node}>
              <b>{c.node}</b>
              <span>{c.protocol || 'any'}{c.host ? ` · ${c.host}` : ''}{c.port ? `:${c.port}` : ''}{c.backend === 'afpacket' ? ' · AF_PACKET' : ''}</span>
              <small>started by {c.requestor || 'unknown'}, expires {c.expiresAt ? new Date(c.expiresAt).toLocaleTimeString() : '—'}</small>
              <div className="toolbar">
                <button className={watching === c.node ? 'primary' : 'btn-secondary'} onClick={() => watch(c.node)}>Watch</button>
                <button className="btn-secondary" onClick={() => stop(c.node)}>Stop</button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">LIVE VIEW</p>
        <h3>{live ? 'Connected' : 'Not connected'}{watching ? ` · ${watching}` : ''} · {filteredIdx.length} of {rows.length} packets shown (last {MAX_LIVE_ROWS})</h3>
        <p>Click Watch on an active session, or start one above, to stream packets here as they're captured.</p>
        {active.length > 1 && (
          <div className="toolbar">
            <span>Switch node:</span>
            {active.map((c) => <button key={c.node} className={watching === c.node ? 'primary' : 'btn-secondary'} onClick={() => watch(c.node)}>{c.node}</button>)}
          </div>
        )}
        <div className="toolbar">
          <label>Protocol{' '}
            <select value={filterProtocol} onChange={(e) => setFilterProtocol(e.target.value)}>
              <option value="">any</option>
              {Object.values(PROTOCOL_NAMES).map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label>Direction{' '}
            <select value={filterDirection} onChange={(e) => setFilterDirection(e.target.value)}>
              <option value="">any</option>
              <option value="1">ingress</option>
              <option value="0">egress</option>
            </select>
          </label>
          <label>Search <input value={filterQuery} onChange={(e) => setFilterQuery(e.target.value)} placeholder="10.0.0.5:443" /></label>
          <button className="btn-secondary" disabled={framesRef.current.length === 0} onClick={download}>Download .pcap ({framesRef.current.length} packets)</button>
        </div>
        <div className="list">
          {rows.length === 0 && <p className="empty-state">No packets yet.</p>}
          {rows.length > 0 && filteredIdx.length === 0 && <p className="empty-state">No packets match this filter.</p>}
          {filteredIdx.slice().reverse().map((i) => {
            const f = rows[i];
            const d = decoded[i];
            return (
              <div className="agent wide" key={i} onClick={() => setExpanded(expanded === i ? null : i)} role="button" tabIndex={0}>
                <b>{PROTOCOL_NAMES[f.protocol] || f.protocol}</b>
                <span>{f.direction === 1 ? 'ingress' : 'egress'} · {f.origLen}B{f.origLen !== f.data.byteLength ? ` (${f.data.byteLength}B captured)` : ''}{d ? ` · ${d.summary}` : ''}</span>
                <small>{new Date(Number(f.observedAtUnixNano / 1_000_000n)).toLocaleTimeString()}</small>
                {expanded === i && <pre>{hexDump(f.data)}</pre>}
              </div>
            );
          })}
        </div>
      </section>

      <CaptureHistory onRepeat={repeat} />
    </div>
  );
}
