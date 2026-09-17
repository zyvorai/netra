import { useEffect, useState } from 'react';
import { api } from '../api';
import AskNetra from '../components/AskNetra';
import { useCountUp } from '../hooks/useCountUp';

function Metric({ value, label }: { value: number | string; label: string }) {
  const numeric = typeof value === 'number' && Number.isFinite(value);
  const animated = useCountUp(numeric ? (value as number) : 0);
  return (
    <div>
      <b>{numeric ? Math.round(animated).toLocaleString() : value}</b>
      <span>{label}</span>
    </div>
  );
}

export default function Overview() {
  const [data, setData] = useState<any>();
  const [obs, setObs] = useState<any>();
  const [health, setHealth] = useState<any>();
  const [l7, setL7] = useState<any>();
  const [insights, setInsights] = useState<any>();
  const [path, setPath] = useState<any>();
  const [drops, setDrops] = useState<any>();
  const [featSummary, setFeatSummary] = useState<{ on?: number; off?: number } | null>(null);
  const [err, setErr] = useState('');

  useEffect(() => {
    Promise.all([
      api('/api/v1/status'),
      api('/api/v1/ebpf/summary'),
      api('/api/v1/ebpf/health?limit=1'),
      api('/api/v1/ebpf/l7?limit=1'),
      api('/api/v1/insights/summary'),
      api('/api/v1/ebpf/path?limit=1'),
      api('/api/v1/ebpf/drops?limit=1'),
      api<{ summary?: { on?: number; off?: number } }>('/api/v1/features'),
    ])
      .then(([s, o, h, l, i, pathDiag, dropDiag, feats]) => {
        setData(s);
        setObs(o);
        setHealth(h);
        setL7(l);
        setInsights(i);
        setPath(pathDiag);
        setDrops(dropDiag);
        setFeatSummary(feats?.summary || null);
        setErr('');
      })
      .catch((e) => setErr(String(e)));
  }, []);

  const fp = data?.fastPath;
  const hs = health?.summary || {};
  const ls = l7?.summary || {};
  const ins = insights || {};
  const topDestinations = obs?.topDestinations || [];
  const topDns = obs?.topDns || [];
  const topProcesses = obs?.topProcesses || [];

  return (
    <div className="grid">
      <AskNetra />
      <section className="card span2">
        <p className="eyebrow">NETRA DATAPATH</p>
        <h3>Independent by default.</h3>
        <p>
          Root-cgroup packet hooks and socket hooks give workload visibility without a CNI dependency. TCX and XDP can be
          layered on selected interfaces. Hubble remains optional.
        </p>
        <div className="metrics">
          <Metric value={data?.agents ?? 0} label="node agents" />
          <Metric value={obs?.packets ?? 0} label="packets counted" />
          <Metric value={obs?.blocked ?? 0} label="blocked packets" />
          <Metric value={obs?.dnsQueries ?? 0} label="DNS events" />
          <Metric value={featSummary?.on ?? '—'} label="features on" />
        </div>
        {fp?.enforceUntil && (
          <p className="warning">Enforcement lease expires {new Date(fp.enforceUntil).toLocaleString()}.</p>
        )}
        {(data?.staleAgents ?? 0) > 0 && (
          <p className="warning">
            One or more agents are stale. Each node independently fails back to observe mode after its controller timeout.
          </p>
        )}
      </section>

      <section className="card span2">
        <p className="eyebrow">STANDALONE / CAPABILITIES</p>
        <h3>Datapath capabilities</h3>
        {err && <p className="warning">{err}</p>}
        {!err && (
          <div className="metrics">
            <Metric value={data?.datapath || '—'} label="datapath" />
            <Metric value={data?.ciliumRequired ? 'Required' : 'Optional'} label="Cilium" />
            <Metric value={data?.hubble ? 'Enabled' : 'Disabled'} label="Hubble" />
            <Metric value={fp?.mode || '—'} label="fast-path mode" />
          </div>
        )}
      </section>

      <section className="card span3">
        <p className="eyebrow">NETWORK HEALTH</p>
        <h3>TCP / DNS score</h3>
        <div className="metrics">
          <Metric value={hs.healthScore ?? '—'} label="health score /100" />
          <Metric value={hs.tcpConnections ?? 0} label="TCP connections" />
          <Metric value={hs.estimatedConnectFailures ?? 0} label="est. TCP failures" />
          <Metric value={hs.dnsFailures ?? 0} label="DNS failures" />
        </div>
        {(hs.anomalies || []).length === 0 && <p className="empty-state">No recent health anomalies.</p>}
        {(hs.anomalies || []).slice(0, 3).map((a: any) => (
          <p key={a.kind + a.subject}>
            <span className={`severity-badge ${a.severity}`}>{a.severity}</span> {a.message || a.kind}
          </p>
        ))}
      </section>

      <section className="card span3">
        <p className="eyebrow">L7 METADATA</p>
        <h3>TLS SNI · HTTP Host</h3>
        <div className="metrics">
          <Metric value={ls.tlsHandshakes ?? 0} label="TLS SNI" />
          <Metric value={ls.httpRequests ?? 0} label="HTTP/1 requests" />
          <Metric value={ls.connectAttempts ?? 0} label="socket attempts" />
          <Metric value={ls.connectBlocked ?? 0} label="blocked attempts" />
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">PATH DIAGNOSTICS</p>
        <h3>TCP connect · pressure</h3>
        <div className="metrics">
          <Metric value={path?.summary?.connectionsMeasured ?? 0} label="connects timed" />
          <Metric value={path?.summary?.congestedFlows ?? 0} label="cwnd-pressure flows" />
          <Metric value={(path?.summary?.lostOut ?? 0) + (path?.summary?.retransOut ?? 0)} label="lost + retrans out" />
          <Metric value={(path?.summary?.anomalies || []).length} label="path signals" />
        </div>
        <p>Full tables live on Path Diagnostics — observe-only sockops path health.</p>
      </section>

      <section className="card span3">
        <p className="eyebrow">DROP DIAGNOSTICS</p>
        <h3>Kernel · softnet · iface</h3>
        <div className="metrics">
          <Metric value={drops?.summary?.kernelDropEvents ?? 0} label="kernel drop events" />
          <Metric value={drops?.summary?.softnetDropped ?? 0} label="softnet dropped" />
          <Metric value={(drops?.summary?.rxDropped ?? 0) + (drops?.summary?.txDropped ?? 0)} label="iface rx+tx drops" />
          <Metric value={(drops?.summary?.anomalies || []).length} label="drop signals" />
        </div>
        <p>Node-level drop reasons live on Drop Diagnostics — optional kfree_skb + stack counters.</p>
      </section>

      <section className="card span3">
        <p className="eyebrow">BEHAVIOR INSIGHTS</p>
        <h3>Dependencies · drift · exposure</h3>
        <div className="metrics">
          <Metric value={ins.dependencyEdges ?? 0} label="dependency edges" />
          <Metric value={ins.driftFindings ?? 0} label="behavior drift" />
          <Metric value={ins.rateDriftFindings ?? 0} label="rate anomalies" />
          <Metric value={ins.highExposure ?? 0} label="high exposure" />
        </div>
        <p>Review-only drafts and rate baselines live on the Insights page — Netra does not auto-enforce learned policy.</p>
      </section>

      <section className="card span2">
        <p className="eyebrow">NETWORK PULSE</p>
        <h3>Kernel-side telemetry</h3>
        <div className="metrics">
          <Metric value={obs?.events ?? 0} label="recent events" />
          <Metric value={obs?.socketEvents ?? 0} label="socket/process events" />
          <Metric value={obs?.protocols?.TCP ?? 0} label="TCP samples" />
          <Metric value={obs?.protocols?.UDP ?? 0} label="UDP samples" />
        </div>
        {(obs?.blockReasons || []).length === 0 && <p className="empty-state">No recent block reasons.</p>}
        {(obs?.blockReasons || []).slice(0, 4).map((x: any) => (
          <p key={x.name}>
            <b>{x.name}</b> · {x.count}
          </p>
        ))}
      </section>

      <section className="card span2">
        <p className="eyebrow">TOP DESTINATIONS / DNS</p>
        <h3>Kernel-observed identities</h3>
        {!topDestinations.length && !topDns.length && !topProcesses.length && (
          <p className="empty-state">No destination, DNS, or process breakdown yet.</p>
        )}
        {topDestinations.length > 0 && (
          <div className="chips">{topDestinations.slice(0, 12).map((x: any) => <span key={'dest-' + x.name}>{x.name} · {x.count}</span>)}</div>
        )}
        {topDns.length > 0 && (
          <div className="chips">{topDns.slice(0, 12).map((x: any) => <span key={'dns-' + x.name}>DNS {x.name} · {x.count}</span>)}</div>
        )}
        {topProcesses.length > 0 && (
          <div className="chips">{topProcesses.slice(0, 12).map((x: any) => <span key={'proc-' + x.name}>{x.name} · {x.count}</span>)}</div>
        )}
      </section>

      <section className="card">
        <h3>Cilium is an integration</h3>
        <p>
          If Cilium/Hubble is installed, Netra can build CiliumNetworkPolicy and show Hubble data — the standalone
          eBPF engine never depends on it.
        </p>
      </section>
    </div>
  );
}
