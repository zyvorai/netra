import { useEffect, useState } from 'react';
import { api } from '../api';
import { classifyMissingMaps } from '../lib/missingMaps';

type FleetNode = {
  node?: string; stale?: boolean; mode?: string; ageSeconds?: number; hooks?: number; programs?: number; attached?: number; workloads?: number; destinations?: number; events?: number;
  cpuPercent?: number; memoryUsedBytes?: number; memoryTotalBytes?: number; loadAvg1?: number;
};
type Inventory = { nodes?: FleetNode[]; agentCount?: number; staleAgents?: number };

type CoverageProgram = { name: string; type?: string; attached: boolean; runCount?: number };
type CoverageNode = { node: string; stale: boolean; mode?: string; hookCount: number; programCount: number; attached: number; detached?: string[]; missingMaps?: string[]; programs?: CoverageProgram[] };
type Coverage = { nodes?: CoverageNode[]; agentCount?: number; staleAgents?: number; detachedPrograms?: number; missingMapEntries?: number; quiet?: boolean };

export default function Fleet() {
  const [inv, setInv] = useState<Inventory>();
  const [cov, setCov] = useState<Coverage>();
  const [clusters, setClusters] = useState<any>();
  const [tenants, setTenants] = useState<any>();
  const [err, setErr] = useState('');
  const load = () => Promise.all([
    api<Inventory>('/api/v1/fleet'),
    api<Coverage>('/api/v1/ebpf/coverage'),
    api<any>('/api/v1/fleet/clusters'),
    api<any>('/api/v1/fleet/tenants'),
  ]).then(([i, c, cl, te]) => {
    setInv(i); setCov(c); setClusters(cl); setTenants(te); setErr('');
  }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">FLEET</p>
        <h3>{inv?.agentCount ?? 0} agents · {inv?.staleAgents ?? 0} stale</h3>
        <p>Compact per-node agent inventory. Observe-only.</p>
        {err && <p className="warning">{err}</p>}
        <div className="list">
          {(inv?.nodes || []).length === 0 && <p className="empty-state">No agents reporting yet.</p>}
          {(inv?.nodes || []).map((n, i) => (
            <div className="agent wide" key={n.node || i}>
              <b>{n.node}</b>
              <span className={n.stale ? 'severity-badge warning' : 'severity-badge info'}>{n.stale ? 'stale' : n.mode || 'observe'}</span>
              <small>
                {n.hooks ?? 0} hooks · {n.attached ?? 0}/{n.programs ?? 0} programs attached · {n.workloads ?? 0} workload cgroups · {n.destinations ?? 0} destinations · {n.ageSeconds ?? 0}s since last report
                {n.memoryTotalBytes ? <> · {n.cpuPercent?.toFixed(0) ?? '—'}% cpu · {Math.round(((n.memoryUsedBytes ?? 0) / n.memoryTotalBytes) * 100)}% mem · load {n.loadAvg1?.toFixed(2) ?? '—'}</> : null}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">PROGRAM COVERAGE</p>
        <h3>{cov?.quiet ? 'All programs attached' : `${cov?.detachedPrograms ?? 0} detached · ${cov?.missingMapEntries ?? 0} missing maps`}</h3>
        <p>Per-node hook/program coverage matrix: attached vs detached programs, missing maps, stale agents. Observe-only — never attaches or detaches anything itself.</p>
        <div className="list">
          {(cov?.nodes || []).length === 0 && <p className="empty-state">No coverage data yet.</p>}
          {(cov?.nodes || []).map((n) => (
            <div className="agent wide" key={n.node}>
              <b>{n.node}</b>
              <span className={n.stale ? 'severity-badge warning' : 'severity-badge info'}>{n.attached}/{n.programCount} attached</span>
              <small>
                {n.hookCount} hooks
                {(n.detached || []).length > 0 && <> · detached: {(n.detached || []).join(', ')}</>}
                {(() => {
                  const classified = classifyMissingMaps(n.missingMaps || []);
                  const bpfMaps = classified.filter((e) => e.kind === 'bpf-map').map((e) => e.raw);
                  const captureIssues = classified.filter((e) => e.kind !== 'bpf-map');
                  return (
                    <>
                      {bpfMaps.length > 0 && <> · missing maps: {bpfMaps.join(', ')}</>}
                      {captureIssues.length > 0 && (
                        <> · capture backend: {captureIssues.map((e) => (e.kind === 'afpacket-backend' ? 'AF_PACKET unavailable (needs CAP_NET_RAW)' : 'eBPF capture object not attached')).join(', ')}</>
                      )}
                    </>
                  );
                })()}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">MULTI-CLUSTER</p>
        <h3>{(clusters?.clusters || clusters?.items || []).length} clusters</h3>
        <p>Read-only aggregator via <code>NETRA_FLEET_PEERS</code>. Observe-only.</p>
        <div className="list">
          {(clusters?.clusters || clusters?.items || []).length === 0 && <p className="empty-state">Only the local cluster is visible (no peers configured).</p>}
          {(clusters?.clusters || clusters?.items || []).map((c: any, i: number) => (
            <div className="agent wide" key={c.name || c.id || i}>
              <b>{c.name || c.id || `cluster ${i + 1}`}</b>
              <small>
                {[c.tenant, c.agentCount != null ? `${c.agentCount} agents` : '', c.staleAgents != null ? `${c.staleAgents} stale` : '', c.reachable === false ? 'unreachable' : '']
                  .filter(Boolean)
                  .join(' · ')}
              </small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">TENANTS</p>
        <h3>{(tenants?.tenants || tenants?.items || []).length} tenant rollups</h3>
        <p>MSSP-style risk rollup from local + peer clusters. Full board also under Surfaces → Fleet.</p>
        <div className="list">
          {(tenants?.tenants || tenants?.items || []).length === 0 && <p className="empty-state">No tenant labels yet — set <code>NETRA_CLUSTER_TENANT</code> on peers.</p>}
          {(tenants?.tenants || tenants?.items || []).map((t: any, i: number) => (
            <div className="agent wide" key={t.tenant || t.name || i}>
              <b>{t.tenant || t.name || `tenant ${i + 1}`}</b>
              <span className="severity-badge info">{t.riskScore != null ? `risk ${t.riskScore}` : t.risk || '—'}</span>
              <small>
                {[t.clusterCount != null ? `${t.clusterCount} clusters` : '', t.agentCount != null ? `${t.agentCount} agents` : '']
                  .filter(Boolean)
                  .join(' · ')}
              </small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
