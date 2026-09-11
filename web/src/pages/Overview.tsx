import { useEffect, useState } from 'react';
import { api } from '../api';
import TerminalFrame from '../components/TerminalFrame';

export default function Overview() {
  const [data, setData] = useState<any>();
  const [obs, setObs] = useState<any>();
  const [health, setHealth] = useState<any>();
  const [l7, setL7] = useState<any>();
  const [insights, setInsights] = useState<any>();
  const [path, setPath] = useState<any>();
  const [drops, setDrops] = useState<any>();
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
    ])
      .then(([s, o, h, l, i, pathDiag, dropDiag]) => {
        setData(s);
        setObs(o);
        setHealth(h);
        setL7(l);
        setInsights(i);
        setPath(pathDiag);
        setDrops(dropDiag);
        setErr('');
      })
      .catch((e) => setErr(String(e)));
  }, []);

  const fp = data?.fastPath;
  const hs = health?.summary || {};
  const ls = l7?.summary || {};
  const ins = insights || {};

  return (
    <div className="grid">
      <section className="card span2">
        <p className="eyebrow">NETRA DATAPATH</p>
        <h2>Independent by default.</h2>
        <p>
          Root-cgroup packet hooks and socket hooks give workload visibility without a CNI dependency. TCX and XDP can be
          layered on selected interfaces. Hubble remains optional.
        </p>
        <div className="metrics">
          <div>
            <b>{data?.agents ?? 0}</b>
            <span>node agents</span>
          </div>
          <div>
            <b>{obs?.packets ?? 0}</b>
            <span>packets counted</span>
          </div>
          <div>
            <b>{obs?.blocked ?? 0}</b>
            <span>blocked packets</span>
          </div>
          <div>
            <b>{obs?.dnsQueries ?? 0}</b>
            <span>DNS events</span>
          </div>
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

      <TerminalFrame title="standalone / capabilities">
        <pre>
          {err ||
            JSON.stringify(
              {
                datapath: data?.datapath,
                ciliumRequired: data?.ciliumRequired,
                hubble: data?.hubble,
                mode: fp?.mode,
              },
              null,
              2,
            )}
        </pre>
      </TerminalFrame>

      <section className="card span2">
        <p className="eyebrow">NETWORK HEALTH</p>
        <h3>TCP / DNS score</h3>
        <div className="metrics">
          <div>
            <b>{hs.healthScore ?? '—'}</b>
            <span>health score /100</span>
          </div>
          <div>
            <b>{hs.tcpConnections ?? 0}</b>
            <span>TCP connections</span>
          </div>
          <div>
            <b>{hs.estimatedConnectFailures ?? 0}</b>
            <span>est. TCP failures</span>
          </div>
          <div>
            <b>{hs.dnsFailures ?? 0}</b>
            <span>DNS failures</span>
          </div>
        </div>
        {(hs.anomalies || []).slice(0, 3).map((a: any) => (
          <p key={a.kind + a.subject}>
            <b>{a.severity}</b> · {a.message || a.kind}
          </p>
        ))}
      </section>

      <section className="card">
        <p className="eyebrow">L7 METADATA</p>
        <h3>TLS SNI · HTTP Host</h3>
        <div className="metrics">
          <div>
            <b>{ls.tlsHandshakes ?? 0}</b>
            <span>TLS SNI</span>
          </div>
          <div>
            <b>{ls.httpRequests ?? 0}</b>
            <span>HTTP/1 requests</span>
          </div>
          <div>
            <b>{ls.connectAttempts ?? 0}</b>
            <span>socket attempts</span>
          </div>
          <div>
            <b>{ls.connectBlocked ?? 0}</b>
            <span>blocked attempts</span>
          </div>
        </div>
      </section>

      <section className="card">
        <p className="eyebrow">PATH DIAGNOSTICS</p>
        <h3>TCP connect · pressure</h3>
        <div className="metrics">
          <div>
            <b>{path?.summary?.connectionsMeasured ?? 0}</b>
            <span>connects timed</span>
          </div>
          <div>
            <b>{path?.summary?.congestedFlows ?? 0}</b>
            <span>cwnd-pressure flows</span>
          </div>
          <div>
            <b>{(path?.summary?.lostOut ?? 0) + (path?.summary?.retransOut ?? 0)}</b>
            <span>lost + retrans out</span>
          </div>
          <div>
            <b>{(path?.summary?.anomalies || []).length}</b>
            <span>path signals</span>
          </div>
        </div>
        <p>Full tables live on Path Diagnostics — observe-only sockops path health.</p>
      </section>

      <section className="card">
        <p className="eyebrow">DROP DIAGNOSTICS</p>
        <h3>Kernel · softnet · iface</h3>
        <div className="metrics">
          <div>
            <b>{drops?.summary?.kernelDropEvents ?? 0}</b>
            <span>kernel drop events</span>
          </div>
          <div>
            <b>{drops?.summary?.softnetDropped ?? 0}</b>
            <span>softnet dropped</span>
          </div>
          <div>
            <b>{(drops?.summary?.rxDropped ?? 0) + (drops?.summary?.txDropped ?? 0)}</b>
            <span>iface rx+tx drops</span>
          </div>
          <div>
            <b>{(drops?.summary?.anomalies || []).length}</b>
            <span>drop signals</span>
          </div>
        </div>
        <p>Node-level drop reasons live on Drop Diagnostics — optional kfree_skb + stack counters.</p>
      </section>

      <section className="card span2">
        <p className="eyebrow">BEHAVIOR INSIGHTS</p>
        <h3>Dependencies · drift · exposure</h3>
        <div className="metrics">
          <div>
            <b>{ins.dependencyEdges ?? 0}</b>
            <span>dependency edges</span>
          </div>
          <div>
            <b>{ins.driftFindings ?? 0}</b>
            <span>behavior drift</span>
          </div>
          <div>
            <b>{ins.rateDriftFindings ?? 0}</b>
            <span>rate anomalies</span>
          </div>
          <div>
            <b>{ins.highExposure ?? 0}</b>
            <span>high exposure</span>
          </div>
        </div>
        <p>Review-only drafts and rate baselines live on the Insights page — Netra does not auto-enforce learned policy.</p>
      </section>

      <section className="card span2">
        <p className="eyebrow">NETWORK PULSE</p>
        <h3>Kernel-side telemetry</h3>
        <div className="metrics">
          <div>
            <b>{obs?.events ?? 0}</b>
            <span>recent events</span>
          </div>
          <div>
            <b>{obs?.socketEvents ?? 0}</b>
            <span>socket/process events</span>
          </div>
          <div>
            <b>{obs?.protocols?.TCP ?? 0}</b>
            <span>TCP samples</span>
          </div>
          <div>
            <b>{obs?.protocols?.UDP ?? 0}</b>
            <span>UDP samples</span>
          </div>
        </div>
        {(obs?.blockReasons || []).slice(0, 4).map((x: any) => (
          <p key={x.name}>
            <b>{x.name}</b> · {x.count}
          </p>
        ))}
      </section>

      <TerminalFrame title="top destinations / DNS">
        <pre>
          {JSON.stringify(
            {
              destinations: obs?.topDestinations ?? [],
              dns: obs?.topDns ?? [],
              processes: obs?.topProcesses ?? [],
            },
            null,
            2,
          )}
        </pre>
      </TerminalFrame>

      <section className="card">
        <h3>Cilium is an integration</h3>
        <p>
          If Cilium/Hubble is installed, Netra can still build CiliumNetworkPolicy and show Hubble identity/verdict data.
          The standalone eBPF engine does not read, write, or depend on Cilium maps.
        </p>
      </section>
    </div>
  );
}
