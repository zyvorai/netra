import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import DNSDiagnostics from '../components/DNSDiagnostics';
import ICMPDiagnostics from '../components/ICMPDiagnostics';
import ExplainFinding from '../components/ExplainFinding';

const ms = (us: number | undefined) => ((us || 0) / 1000).toFixed((us || 0) >= 100000 ? 0 : 1);
const pct = (n: number, d: number) => d ? `${(n * 100 / d).toFixed(1)}%` : '0%';

export default function Health() {
  const [data, setData] = useState<any>();
  const [summary, setSummary] = useState<any>();
  const [agents, setAgents] = useState<any[]>([]);
  const [err, setErr] = useState('');
  const load = () => Promise.all([
    api<any>('/api/v1/ebpf/health?limit=50'),
    api<any>('/api/v1/ebpf/summary'),
    api<any>('/api/v1/agents'),
  ]).then(([x, s, a]) => { setData(x); setSummary(s); setAgents(a.items || []); setErr(''); }).catch(e => setErr(String(e)));
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
      <p className="eyebrow">UDP PULSE</p>
      <div className="metrics">
        <div><b>{s.udpFlows || 0}</b><span>flows</span></div>
        <div><b>{s.udpPackets || 0}</b><span>packets</span></div>
        <div><b>{s.udpBytes || 0}</b><span>bytes</span></div>
      </div>
      <p>Cgroup-attributed UDP flow counters beyond DNS. No send-failure signal is tracked: no BPF hook Netra attaches can see a UDP send fail after the fact.</p>
    </section>

    <section className="card span3">
      <p className="eyebrow">QUIC OBSERVED</p>
      <div className="metrics">
        <div><b>{s.quicObservedFlows || 0}</b><span>UDP/443 flows</span></div>
        <div><b>{s.quicLongHeaderPackets || 0}</b><span>long-header packets</span></div>
      </div>
      <p>A traffic-observation heuristic on UDP/443 packets matching RFC 9000's long-header wire form — <b>not SNI extraction</b>. Full QUIC SNI parsing is infeasible in BPF: RFC 9001 mandatorily applies header protection to Initial packets, requiring crypto helpers (HKDF-SHA256, AES-128/ChaCha20) that don't exist in BPF.</p>
    </section>

    <DNSDiagnostics agents={agents} />

    {agents.some((a: any) => (a.missingMaps || []).length) && (
      <section className="card span3">
        <p className="eyebrow">BPF OBJECT</p>
        <h3>Agent maps missing</h3>
        <p className="warning">Rebuild and roll the agent image so allow/rate/icmp maps exist. Until then those controls fail open.</p>
        {agents.filter((a: any) => (a.missingMaps || []).length).map((a: any) => (
          <div className="agent wide" key={a.node}>
            <b>{a.node}</b><small>{(a.missingMaps || []).join(', ')}</small>
            <ExplainFinding page="health" kind="bpf-maps-missing" subject={a.node} message={(a.missingMaps || []).join(', ')} />
          </div>
        ))}
      </section>
    )}
    <section className="card span3">
      <p className="eyebrow">RATE DROPS</p>
      <h3>PPS ceilings that actually fired</h3>
      <div className="list">
        {agents.flatMap((a: any) => (a.rateDrops || []).map((c: any) => ({ ...c, node: a.node }))).length === 0 && <p className="empty-state">No destination has been rate-dropped yet.</p>}
        {agents.flatMap((a: any) => (a.rateDrops || []).map((c: any) => ({ ...c, node: a.node }))).sort((a: any, b: any) => (b.count || 0) - (a.count || 0)).slice(0, 16).map((c: any, i: number) => (
          <div className="agent wide" key={i}>
            <b>{c.name}</b><span>{c.node}</span><small>{c.count} dropped</small>
            <ExplainFinding page="health" kind="rate-drop" subject={c.name} message={`${c.count} dropped at ${c.node}`} />
          </div>
        ))}
      </div>
    </section>
    <section className="card span3">
      <p className="eyebrow">BYTE-RATE DROPS</p>
      <h3>BPS ceilings that actually fired</h3>
      <div className="list">
        {agents.flatMap((a: any) => (a.byteRateDrops || []).map((c: any) => ({ ...c, node: a.node }))).length === 0 && <p className="empty-state">No destination has hit its byte-rate cap yet.</p>}
        {agents.flatMap((a: any) => (a.byteRateDrops || []).map((c: any) => ({ ...c, node: a.node }))).sort((a: any, b: any) => (b.count || 0) - (a.count || 0)).slice(0, 16).map((c: any, i: number) => (
          <div className="agent wide" key={i}>
            <b>{c.name}</b><span>{c.node}</span><small>{c.count} dropped</small>
          </div>
        ))}
      </div>
    </section>
    <section className="card span3">
      <p className="eyebrow">CONNECTION-RATE DROPS</p>
      <h3>New-TCP-connection caps that actually fired</h3>
      <div className="list">
        {agents.flatMap((a: any) => (a.connRateDrops || []).map((c: any) => ({ ...c, node: a.node }))).length === 0 && <p className="empty-state">No workload has hit its connection-rate cap yet.</p>}
        {agents.flatMap((a: any) => (a.connRateDrops || []).map((c: any) => ({ ...c, node: a.node }))).sort((a: any, b: any) => (b.count || 0) - (a.count || 0)).slice(0, 16).map((c: any, i: number) => (
          <div className="agent wide" key={i}>
            <b>{c.name}</b><span>{c.node}</span><small>{c.count} dropped</small>
          </div>
        ))}
      </div>
    </section>
    <section className="card span3">
      <p className="eyebrow">ICMP PULSE</p>
      <h3>Type histogram from the packet path</h3>
      <p>Observe-only. Cumulative since the map was last created. No ICMP payload is exported.</p>
      <div className="list">
        {agents.flatMap((a: any) => [...(a.icmpTypes || []).map((c: any) => ({ ...c, node: a.node, fam: 'v4' })), ...(a.icmp6Types || []).map((c: any) => ({ ...c, node: a.node, fam: 'v6' }))]).length === 0 && (
          <p className="empty-state">No ICMP types recorded yet. Rebuild the agent BPF object so icmp_type_stats exists.</p>
        )}
        {agents.flatMap((a: any) => [
          ...(a.icmpTypes || []).map((c: any) => ({ ...c, node: a.node, fam: 'icmp' })),
          ...(a.icmp6Types || []).map((c: any) => ({ ...c, node: a.node, fam: 'icmp6' })),
        ]).sort((a: any, b: any) => (b.count || 0) - (a.count || 0)).slice(0, 20).map((c: any, i: number) => (
          <div className="agent wide" key={i}>
            <b>{c.fam}/{c.name}</b><span>{c.node}</span><small>{c.count} messages</small>
            <ExplainFinding page="health" kind={`icmp:${c.name}`} subject={c.node} message={`${c.count} ${c.fam} ${c.name}`} />
          </div>
        ))}
      </div>
    </section>

    <ICMPDiagnostics agents={agents} />

    <section className="card span3">
      <p className="eyebrow">HEALTH SIGNALS</p>
      <h3>Heuristic anomalies</h3>
      <p>These are deterministic operational thresholds, not ML/statistical anomaly claims.</p>
      <div className="list">
        {anomalies.length === 0 && <p className="empty-state">No threshold-based network health signals in the latest reports.</p>}
        {anomalies.slice(0, 25).map((a:any, i:number) => <div className="agent wide" key={i}><b>{a.kind}</b><span className={`severity-badge ${a.severity}`}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small><ExplainFinding page="health" kind={a.kind} subject={a.subject} message={a.message} severity={a.severity} /></div>)}
        {anomalies.length > 25 && <p className="empty-state">+{anomalies.length - 25} more not shown.</p>}
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">TCP HEALTH</p>
      <h3>Sockops exact state</h3>
      {(data?.tcp || []).length === 0 && <p className="empty-state">No TCP sockops samples yet.</p>}
      {(data?.tcp || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD / PROCESS</span><span>REMOTE</span><span>RTT</span><span>LOSS SIGNALS</span><span>CONNECTION</span></div>
        {(data?.tcp || []).map((t:any, i:number) => {
          const who = `${t.namespace ? `${t.namespace}/${t.pod}` : (t.comm || `cgroup ${t.cgroupId || 0}`)}${t.pid ? ` · pid=${t.pid}` : ''}${t.exe ? ` · ${t.exe}` : ''}${t.ownershipStale ? ' · stale-owner' : ''}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{t.remoteIp}:{t.remotePort}</span>
            <span>{ms(t.srttUs)} ms · min {ms(t.minRttUs)} ms</span>
            <span>retrans {t.retransmissions} · RTO {t.rtos}</span>
            <span>active {t.activeEstablished} · passive {t.passiveEstablished} · close {t.closes}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">DNS HEALTH</p>
      <h3>Matched UDP/53 transactions</h3>
      {(data?.dns || []).length === 0 && <p className="empty-state">No DNS transactions matched yet.</p>}
      {(data?.dns || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>NAME</span><span>QUERIES</span><span>FAILURES</span><span>LATENCY</span></div>
        {(data?.dns || []).map((d:any, i:number) => {
          const who = d.namespace ? `${d.namespace}/${d.pod}` : `cgroup ${d.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span className="truncate" title={d.name} aria-label={d.name}>{d.name}</span>
            <span>{d.queries} / {d.responses} matched</span>
            <span>{d.failures} · {pct(d.failures, d.responses)}</span>
            <span>avg {ms(d.responses ? d.totalLatencyUs / d.responses : 0)} ms · max {ms(d.maxLatencyUs)} ms</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">UDP FLOW HEALTH</p>
      <h3>Packets/bytes per remote endpoint</h3>
      {(data?.udp || []).length === 0 && <p className="empty-state">No cgroup-attributed UDP flows observed yet.</p>}
      {(data?.udp || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>PACKETS</span><span>BYTES</span></div>
        {(data?.udp || []).map((u:any, i:number) => {
          const who = u.namespace ? `${u.namespace}/${u.pod}` : `cgroup ${u.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{u.remoteIp}:{u.remotePort}</span>
            <span>{u.packets}</span>
            <span>{u.bytes}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">QUIC-OBSERVED FLOWS</p>
      <h3>UDP/443 long-header packets by remote endpoint</h3>
      {(data?.quic || []).length === 0 && <p className="empty-state">No QUIC-observed traffic yet.</p>}
      {(data?.quic || []).length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>LONG-HEADER</span><span>TOTAL UDP/443</span></div>
        {(data?.quic || []).map((q:any, i:number) => {
          const who = q.namespace ? `${q.namespace}/${q.pod}` : `cgroup ${q.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{q.remoteIp}:{q.remotePort}</span>
            <span>{q.longHeaderPackets}</span>
            <span>{q.packets}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">TCP RESET SIGNALS</p>
      <h3>Handshake / reset counters</h3>
      {resetRows.length === 0 && <p className="empty-state">No TCP reset signals in the latest reports.</p>}
      {resetRows.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>SYN</span><span>SYN-ACK</span><span>FIN</span><span>RST / PACKETS</span></div>
        {resetRows.map((r:any, i:number) => {
          const who = r.namespace ? `${r.namespace}/${r.pod}` : `cgroup ${r.cgroupId || 0}`;
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}</span>
            <span>{r.syn}</span><span>{r.synAck}</span><span>{r.fin}</span><span>{r.rst} / {r.packets}</span>
          </div>;
        })}
      </div>}
    </section>

    <section className="card">
      <p className="eyebrow">KERNEL PULSE</p>
      <h3>What Netra sees</h3>
      <div className="metrics">
        <div><b>{summary?.packets ?? 0}</b><span>packets</span></div>
        <div><b>{summary?.blocked ?? 0}</b><span>blocked</span></div>
        <div><b>{summary?.dnsQueries ?? 0}</b><span>DNS</span></div>
        <div><b>{summary?.socketEvents ?? 0}</b><span>socket events</span></div>
      </div>
      {Object.entries(summary?.hooks || {}).length === 0 &&
        !(summary?.blockReasons || []).length &&
        !(summary?.topDns || []).length &&
        !(summary?.topProcesses || []).length &&
        !(summary?.topWorkloads || []).length &&
        !(summary?.topBlockedWorkloads || []).length && (
        <p className="empty-state">No kernel-side breakdown yet.</p>
      )}
      {Object.entries(summary?.hooks || {}).length > 0 && (
        <div className="chips">{Object.entries(summary.hooks as Record<string, number>).map(([name, count]) => <span key={'hook-'+name}>{name} · {count}</span>)}</div>
      )}
      {(summary?.blockReasons || []).length > 0 && (
        <div className="chips">{summary.blockReasons.slice(0, 12).map((x: any) => <span key={'reason-'+x.name}>{x.name} · {x.count}</span>)}</div>
      )}
      {(summary?.topDns || []).length > 0 && (
        <div className="chips">{summary.topDns.slice(0, 12).map((x: any) => <span key={'dns-'+x.name}>DNS {x.name} · {x.count}</span>)}</div>
      )}
      {(summary?.topProcesses || []).length > 0 && (
        <div className="chips">{summary.topProcesses.slice(0, 12).map((x: any) => <span key={'proc-'+x.name}>{x.name} · {x.count}</span>)}</div>
      )}
      {(summary?.topWorkloads || []).length > 0 && (
        <div className="chips">{summary.topWorkloads.slice(0, 12).map((x: any) => <span key={'wl-'+x.name}>{x.name} · {x.count}</span>)}</div>
      )}
      {(summary?.topBlockedWorkloads || []).length > 0 && (
        <div className="chips">{summary.topBlockedWorkloads.slice(0, 12).map((x: any) => <span key={'blk-'+x.name}>{x.name} · {x.count}</span>)}</div>
      )}
    </section>
    <section className="card span2"><p className="eyebrow">BPF PROGRAM HEALTH</p><h3>Attach state and run stats</h3><p>Per-node program attach flags plus kernel run counts when BPF stats are enabled. Use this when a hook is missing after upgrade or verifier load failures.</p>{agents.map(a => <div className="agent wide" key={'prog-'+a.node}><b>{a.node}</b><span>{a.stale ? 'stale' : `${(a.programs || []).filter((p:any)=>p.attached).length}/${(a.programs || []).length} attached`}</span><small>{(a.programs || []).length === 0 ? 'no program report yet' : (a.programs || []).map((p:any) => `${p.name}${p.attached ? '' : ' (detached)'}: runs=${p.runCount || 0}`).join(' · ')}</small></div>)}</section>
    <section className="card span3"><p className="eyebrow">NETWORK HISTOGRAMS</p><h3>Retransmit / RTT / connect buckets</h3><p>Agent-side histograms from existing sockops samples, plus listen overflow and softirq NET_RX counters. Softirq entry→exit latency remains deferred.</p>{agents.map(a => {
      const h = a.histograms;
      if (!h) return <div className="agent wide" key={'hist-'+a.node}><b>{a.node}</b><span>—</span></div>;
      return <div className="agent wide" key={'hist-'+a.node}><b>{a.node}</b><span>retrans n={h.tcpRetransmissions?.count || 0} · srtt n={h.tcpSrttUs?.count || 0} · connect n={h.tcpConnectUs?.count || 0}</span><small>listen overflows={h.host?.listenOverflows || 0} · listen drops={h.host?.listenDrops || 0} · softirq NET_RX={h.host?.softirqNetRx || 0}</small></div>;
    })}</section>
  </div>;
}
