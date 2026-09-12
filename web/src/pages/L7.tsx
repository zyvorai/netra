import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import TerminalFrame from '../components/TerminalFrame';

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

    <div className="span3"><TerminalFrame title="tls clienthello · parsed sni metadata">
      <div className="flowhead obs"><span>WORKLOAD</span><span>SNI</span><span>HANDSHAKES</span><span>BLOCKED</span><span>CGROUP</span></div>
      {(data?.tls || []).map((x:any, i:number) => <div className="flowrow obs" key={i}>
        <span>{x.namespace ? `${x.namespace}/${x.pod}` : 'node/unresolved'}</span><span>{x.sni}</span><span>{x.handshakes}</span><span className={x.blocked ? 'blocked' : ''}>{x.blocked}</span><span>{x.cgroupId || 0}</span>
      </div>)}
    </TerminalFrame></div>

    <div className="span3"><TerminalFrame title="cleartext http/1 · method + host only">
      <div className="flowhead obs"><span>WORKLOAD</span><span>METHOD</span><span>HOST</span><span>REQUESTS</span><span>CGROUP</span></div>
      {(data?.http || []).map((x:any, i:number) => <div className="flowrow obs" key={i}>
        <span>{x.namespace ? `${x.namespace}/${x.pod}` : 'node/unresolved'}</span><span>{x.method}</span><span>{x.host}</span><span>{x.requests}</span><span>{x.cgroupId || 0}</span>
      </div>)}
    </TerminalFrame></div>

    <div className="span3"><TerminalFrame title="socket attempts · exact destination counters">
      <div className="flowhead obs"><span>WORKLOAD</span><span>PROTO</span><span>REMOTE</span><span>ATTEMPTS</span><span>BLOCKED</span></div>
      {connections.map((x:any, i:number) => <div className="flowrow obs" key={i}>
        <span>{x.namespace ? `${x.namespace}/${x.pod}` : `cgroup ${x.cgroupId || 0}`}</span><span>{x.protocol}</span><span>{x.remoteIp}:{x.remotePort}</span><span>{x.attempts}</span><span className={x.blocked ? 'blocked' : ''}>{x.blocked}</span>
      </div>)}
    </TerminalFrame></div>
  </div>;
}
