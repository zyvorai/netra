import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';

type Summary = {
  dependencyEdges: number;
  externalEdges: number;
  baselineEntries: number;
  driftFindings: number;
  recommendations: number;
};

type Node = { id: string; kind: string; namespace?: string; name: string; ip?: string; workloadKind?: string };
type Edge = { source: string; target: string; protocol: string; port?: number; packets: number; bytes: number; blocked: number; external?: boolean };
type Graph = { generatedAt: string; nodes: Node[]; edges: Edge[] };
type Drift = { baselineCapturedAt?: string; findings: { severity: string; kind: string; source: string; value: string; count?: number; message: string }[] };
type Recommendation = { id: string; kind: string; namespace: string; workloadKind?: string; workloadName: string; confidence: string; rationale: string[]; manifest?: any };

export default function Insights() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [drift, setDrift] = useState<Drift | null>(null);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [ciliumEnabled, setCiliumEnabled] = useState(false);
  const [baseline, setBaseline] = useState<any>(null);
  const [msg, setMsg] = useState('');

  async function refresh() {
    try {
      const [s, g, d, r, b] = await Promise.all([
        api<Summary>('/api/v1/insights/summary'),
        api<Graph>('/api/v1/insights/dependencies?limit=250'),
        api<Drift>('/api/v1/insights/drift'),
        api<any>('/api/v1/insights/recommendations?limit=30'),
        api<any>('/api/v1/insights/baseline'),
      ]);
      setSummary(s); setGraph(g); setDrift(d); setRecommendations(r.items || []); setCiliumEnabled(Boolean(r.ciliumEnabled)); setBaseline(b); setMsg('');
    } catch (e) { setMsg(String(e)); }
  }

  useEffect(() => { void refresh(); }, []);

  const nodeByID = useMemo(() => new Map((graph?.nodes || []).map((n) => [n.id, n])), [graph]);
  const label = (id: string) => {
    const n = nodeByID.get(id);
    if (!n) return id;
    if (n.kind === 'external') return n.ip || n.name;
    return `${n.namespace || ''}/${n.name}`.replace(/^\//, '');
  };

  async function capture() {
    try { const x = await api<any>('/api/v1/insights/baseline', { method: 'POST' }); setBaseline(x); setMsg(`Baseline captured with ${x.baseline?.entries?.length || 0} entries.`); await refresh(); }
    catch (e) { setMsg(String(e)); }
  }
  async function clear() {
    if (!confirm('Clear the known-good behavior baseline?')) return;
    try { await api('/api/v1/insights/baseline', { method: 'DELETE', headers: { 'X-Netra-Confirm-Baseline-Clear': 'clear' } }); setMsg('Baseline cleared.'); await refresh(); }
    catch (e) { setMsg(String(e)); }
  }

  return <div className="grid">
    <section className="card span3">
      <p className="eyebrow">BEHAVIOR INTELLIGENCE</p>
      <h2>Dependencies, drift, and policy drafts.</h2>
      <p>Netra resolves exact eBPF counters into Kubernetes dependencies, remembers a known-good behavior set, and surfaces what appeared afterward. Recommendations are drafts only—review and preflight before applying.</p>
      {msg && <p className="warning">{msg}</p>}
      <div className="metrics">
        <div><b>{summary?.dependencyEdges ?? '—'}</b><span>dependency edges</span></div>
        <div><b>{summary?.externalEdges ?? '—'}</b><span>external edges</span></div>
        <div><b>{summary?.driftFindings ?? '—'}</b><span>new behaviors</span></div>
        <div><b>{summary?.recommendations ?? '—'}</b><span>policy drafts</span></div>
      </div>
    </section>

    <section className="card">
      <p className="eyebrow">KNOWN GOOD</p>
      <h3>Behavior baseline</h3>
      <p>{baseline?.captured ? `Captured ${new Date(baseline.baseline?.capturedAt || Date.now()).toLocaleString()} · ${baseline.baseline?.entries?.length ?? 0} entries` : 'No baseline captured yet.'}</p>
      <div className="toolbar"><button className="primary" onClick={capture}>{baseline?.captured ? 'Recapture' : 'Capture baseline'}</button><button onClick={clear} disabled={!baseline?.captured}>Clear</button></div>
    </section>

    <section className="card span2">
      <p className="eyebrow">DRIFT</p>
      <h3>New behavior after baseline</h3>
      {!drift?.baselineCapturedAt && <p>Capture a baseline to begin drift detection.</p>}
      <div className="list insightlist">
        {(drift?.findings || []).slice(0, 30).map((f, i) => <div className={`insightrow ${f.severity}`} key={`${f.source}-${f.kind}-${f.value}-${i}`}>
          <b>{f.kind}</b><span>{f.source}</span><code>{f.value}</code><small>{f.count || 0} observations · {f.message}</small>
        </div>)}
        {drift?.baselineCapturedAt && !(drift.findings || []).length && <p>No new behavior crossed the noise thresholds.</p>}
      </div>
    </section>

    <section className="card span3">
      <p className="eyebrow">DEPENDENCY GRAPH</p>
      <h3>Workload → workload/service/external</h3>
      <div className="flowhead deps"><span>SOURCE</span><span>TARGET</span><span>NETWORK</span><span>PACKETS / BYTES</span></div>
      {(graph?.edges || []).slice(0, 100).map((e, i) => <div className="flowrow deps" key={`${e.source}-${e.target}-${e.protocol}-${e.port}-${i}`}>
        <span>{label(e.source)}</span><span>{label(e.target)} {e.external ? '↗' : ''}</span><span>{e.protocol}{e.port ? `/${e.port}` : ''}</span><span>{e.packets.toLocaleString()} / {e.bytes.toLocaleString()}</span>
      </div>)}
      {graph && !(graph.edges || []).length && <p>No workload egress counters are available yet.</p>}
    </section>

    <section className="card span3">
      <p className="eyebrow">POLICY RECOMMENDATIONS</p>
      <h3>Observed-traffic CiliumNetworkPolicy drafts</h3>
      <p>These are intentionally medium-confidence drafts. Observed traffic is not proof that every application path has been exercised.</p>
      {!ciliumEnabled && <p className="warning">Cilium integration is currently disabled. Drafts can be reviewed/exported, but live Cilium policy operations remain disabled.</p>}
      <div className="recommendations">
        {recommendations.map((r) => <details key={r.id} className="recommendation">
          <summary><b>{r.namespace}/{r.workloadName}</b><span>{r.confidence} confidence · {r.kind}</span></summary>
          {r.rationale.map((x) => <p key={x}>• {x}</p>)}
          <pre>{JSON.stringify(r.manifest, null, 2)}</pre>
        </details>)}
        {!recommendations.length && <p>No draft can be generated yet. Netra needs workload labels plus observed egress dependencies.</p>}
      </div>
    </section>
  </div>;
}
