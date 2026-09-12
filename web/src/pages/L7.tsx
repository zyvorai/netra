import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';

export default function L7() {
  const [data, setData] = useState<any>();
  const [cfg, setCfg] = useState<any>();
  const [sni, setSNI] = useState('');
  const [err, setErr] = useState('');

  const load = () => Promise.all([
    api<any>('/api/v1/ebpf/l7?limit=200'),
    api<any>('/api/v1/ebpf/config'),
  ]).then(([d, c]) => { setData(d); setCfg(c); setErr(''); }).catch(e => setErr(String(e)));

  useEffect(() => { void load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  async function mutate(path: string, name: string) {
    try {
      await api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
      setSNI('');
      await load();
    } catch (e) { setErr(String(e)); }
  }

  const sum = data?.summary || {};
  const connections = useMemo(() => (data?.connections || []).slice(0, 200), [data]);

  return <div className="grid">
    {err && <section className="card span3"><p className="warning">{err}</p></section>}

    <section className="card span3">
      <p className="eyebrow">L7 PULSE</p>
      <div className="metrics">
        <div><b>{sum.tlsHandshakes || 0}</b><span>TLS SNI handshakes</span></div>
        <div><b>{sum.uniqueSni || 0}</b><span>unique SNI</span></div>
        <div><b>{sum.httpRequests || 0}</b><span>HTTP/1 requests</span></div>
        <div><b>{sum.uniqueHttpHosts || 0}</b><span>HTTP hosts</span></div>
        <div><b>{sum.connectAttempts || 0}</b><span>socket attempts</span></div>
        <div><b>{sum.connectBlocked || 0}</b><span>blocked attempts</span></div>
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">TLS SNI CONTAINMENT</p>
      <h3>Exact SNI deny</h3>
      <p>This is a leased emergency control. A rule only blocks when Netra successfully parses the exact SNI from a ClientHello in the current skb; unparsed, fragmented, ECH, or QUIC traffic fails open for this rule.</p>
      <div className="toolbar">
        <input value={sni} onChange={e => setSNI(e.target.value)} placeholder="telemetry.example.com" />
        <button className="primary" onClick={() => mutate('/api/v1/ebpf/sni', sni)} disabled={!sni.trim()}>Add SNI</button>
      </div>
      <div className="chips">{(cfg?.blockedSni || []).map((x: string) => <button key={x} onClick={() => mutate('/api/v1/ebpf/sni/delete', x)}>{x} ×</button>)}</div>
    </section>

    <section className="card span3">
      <p className="eyebrow">TOP IDENTITIES</p>
      <div className="chips">{(sum.topSni || []).slice(0, 12).map((x:any) => <span key={'s'+x.name}>TLS {x.name} · {x.count}</span>)}</div>
      <div className="chips">{(sum.topHttpHosts || []).slice(0, 12).map((x:any) => <span key={'h'+x.name}>HTTP {x.name} · {x.count}</span>)}</div>
      <div className="chips">{(sum.topRemotePorts || []).slice(0, 12).map((x:any) => <span key={'p'+x.name}>{x.name} · {x.count}</span>)}</div>
    </section>

    <section className="card span3">
      <p className="eyebrow">TLS CLIENTHELLO</p><h3>Parsed SNI metadata</h3>
      {(data?.tls || []).length === 0 && <p className="empty-state">No TLS ClientHello samples yet.</p>}
      {(data?.tls || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>SNI</span><span>HANDSHAKES</span><span>BLOCKED</span><span>CGROUP</span></div>
        {(data?.tls || []).map((x:any, i:number) => {
          const who = x.namespace ? `${x.namespace}/${x.pod}` : 'node/unresolved';
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who}>{who}</span><span className="truncate" title={x.sni}>{x.sni}</span><span>{x.handshakes}</span><span className={x.blocked ? 'blocked' : ''}>{x.blocked}</span><span>{x.cgroupId || 0}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">CLEARTEXT HTTP/1</p><h3>Method + host only</h3>
      {(data?.http || []).length === 0 && <p className="empty-state">No cleartext HTTP/1 samples yet.</p>}
      {(data?.http || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>METHOD</span><span>HOST</span><span>REQUESTS</span><span>CGROUP</span></div>
        {(data?.http || []).map((x:any, i:number) => {
          const who = x.namespace ? `${x.namespace}/${x.pod}` : 'node/unresolved';
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who}>{who}</span><span>{x.method}</span><span className="truncate" title={x.host}>{x.host}</span><span>{x.requests}</span><span>{x.cgroupId || 0}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">SOCKET ATTEMPTS</p><h3>Exact destination counters</h3>
      {connections.length === 0 && <p className="empty-state">No socket attempt samples yet.</p>}
      {connections.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>PROTO</span><span>REMOTE</span><span>ATTEMPTS</span><span>BLOCKED</span></div>
        {connections.map((x:any, i:number) => {
          const who = x.namespace ? `${x.namespace}/${x.pod}` : `cgroup ${x.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who}>{who}</span><span>{x.protocol}</span><span>{x.remoteIp}:{x.remotePort}</span><span>{x.attempts}</span><span className={x.blocked ? 'blocked' : ''}>{x.blocked}</span>
          </div>;
        })}
      </div>}
    </section>
  </div>;
}
