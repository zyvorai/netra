import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import TerminalFrame from '../components/TerminalFrame';

const ms = (us: number | undefined) => ((us || 0) / 1000).toFixed((us || 0) >= 100000 ? 0 : 1);
const pct = (n: number, d: number) => d ? `${(n * 100 / d).toFixed(1)}%` : '0%';

export default function Health() {
  const [data, setData] = useState<any>();
  const [err, setErr] = useState('');
  const load = () => api<any>('/api/v1/ebpf/health?limit=50').then(x => { setData(x); setErr(''); }).catch(e => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);
  const s = data?.summary || {};
  const anomalies = data?.summary?.anomalies || [];
  const resetRows = useMemo(() => (data?.signals || []).filter((x:any) => x.rst > 0).sort((a:any,b:any)=>b.rst-a.rst).slice(0,50), [data]);

  return <div className="grid">
    {err && <section className="card span3"><p className="warning">{err}</p></section>}

    <section className="card span3">
      <p className="eyebrow">TCP PULSE</p>
      <div className="metrics">
        <div><b>{s.tcpConnections || 0}</b><span>connections</span></div>
        <div><b>{ms(s.averageSrttUs)} ms</b><span>avg SRTT</span></div>
        <div><b>{s.tcpRetransmissions || 0}</b><span>retransmits</span></div>
        <div><b>{s.tcpRtos || 0}</b><span>RTOs</span></div>
        <div><b>{s.tcpResets || 0}</b><span>RST packets</span></div><div><b>{s.healthScore ?? 100}</b><span>health score /100</span></div><div><b>{s.connectionAttempts || 0}</b><span>socket attempts</span></div><div><b>{s.estimatedConnectFailures || 0}</b><span>est. TCP failures</span></div>
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">DNS PULSE</p>
      <div className="metrics">
        <div><b>{s.dnsQueries || 0}</b><span>queries</span></div>
        <div><b>{s.dnsResponses || 0}</b><span>matched responses</span></div>
        <div><b>{s.dnsFailures || 0}</b><span>rcode failures</span></div>
        <div><b>{ms(s.averageDnsLatencyUs)} ms</b><span>avg latency</span></div>
        <div><b>{ms(s.maxDnsLatencyUs)} ms</b><span>max latency</span></div>
      </div>
      <p>Failure rate: <b>{pct(s.dnsFailures || 0, s.dnsResponses || 0)}</b>. DNS timing covers matched plain UDP/53 transactions only; DoH, DoT and TCP DNS are intentionally not inferred.</p>
    </section>

    <section className="card span3">
      <p className="eyebrow">HEALTH SIGNALS</p>
      <h3>Heuristic anomalies</h3>
      <p>These are deterministic operational thresholds, not ML/statistical anomaly claims.</p>
      <div className="list">
        {anomalies.length === 0 && <p>No threshold-based network health signals in the latest reports.</p>}
        {anomalies.map((a:any, i:number) => <div className="agent wide" key={i}><b>{a.kind}</b><span className={a.severity === 'critical' ? 'blocked' : ''}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small></div>)}
      </div>
    </section>

    <div className="span3"><TerminalFrame title="tcp health · sockops exact state">
      <div className="flowhead obs"><span>WORKLOAD / PROCESS</span><span>REMOTE</span><span>RTT</span><span>LOSS SIGNALS</span><span>CONNECTION</span></div>
      {(data?.tcp || []).map((t:any, i:number) => <div className="flowrow obs" key={i}>
        <span>{t.namespace ? `${t.namespace}/${t.pod}` : (t.comm || `cgroup ${t.cgroupId || 0}`)}{t.pid ? ` · pid=${t.pid}` : ''}{t.exe ? ` · ${t.exe}` : ''}{t.ownershipStale ? ' · stale-owner' : ''}</span>
        <span>{t.remoteIp}:{t.remotePort}</span>
        <span>{ms(t.srttUs)} ms · min {ms(t.minRttUs)} ms</span>
        <span>retrans {t.retransmissions} · RTO {t.rtos}</span>
        <span>active {t.activeEstablished} · passive {t.passiveEstablished} · close {t.closes}</span>
      </div>)}
    </TerminalFrame></div>

    <div className="span3"><TerminalFrame title="dns health · matched udp/53 transactions">
      <div className="flowhead obs"><span>WORKLOAD</span><span>NAME</span><span>QUERIES</span><span>FAILURES</span><span>LATENCY</span></div>
      {(data?.dns || []).map((d:any, i:number) => <div className="flowrow obs" key={i}>
        <span>{d.namespace ? `${d.namespace}/${d.pod}` : `cgroup ${d.cgroupId || 0}`}</span>
        <span>{d.name}</span>
        <span>{d.queries} / {d.responses} matched</span>
        <span>{d.failures} · {pct(d.failures, d.responses)}</span>
        <span>avg {ms(d.responses ? d.totalLatencyUs / d.responses : 0)} ms · max {ms(d.maxLatencyUs)} ms</span>
      </div>)}
    </TerminalFrame></div>

    <div className="span3"><TerminalFrame title="tcp reset / handshake signals">
      <div className="flowhead obs"><span>WORKLOAD</span><span>SYN</span><span>SYN-ACK</span><span>FIN</span><span>RST / PACKETS</span></div>
      {resetRows.map((r:any, i:number) => <div className="flowrow obs" key={i}>
        <span>{r.namespace ? `${r.namespace}/${r.pod}` : `cgroup ${r.cgroupId || 0}`}</span>
        <span>{r.syn}</span><span>{r.synAck}</span><span>{r.fin}</span><span>{r.rst} / {r.packets}</span>
      </div>)}
    </TerminalFrame></div>
  </div>;
}
