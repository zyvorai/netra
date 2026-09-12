import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';

type Summary = {
  dependencyEdges: number; externalEdges: number; baselineEntries: number; driftFindings: number; recommendations: number;
  rateBaselineEntries: number; rateDriftFindings: number; highExposure: number; remediationProposals: number; rateWarming: boolean;
};
type Node = { id: string; kind: string; namespace?: string; name: string; ip?: string; workloadKind?: string };
type Edge = { source: string; target: string; protocol: string; port?: number; packets: number; bytes: number; blocked: number; external?: boolean };
type Graph = { generatedAt: string; nodes: Node[]; edges: Edge[] };
type Drift = { baselineCapturedAt?: string; findings: { severity: string; kind: string; source: string; value: string; count?: number; message: string }[] };
type RateFinding = { severity: string; source: string; metric: string; baselineRate: number; currentRate: number; ratio?: number; message: string };
type RateDrift = { baselineCapturedAt?: string; window: { warming: boolean; requestedWindowSeconds: number; metrics: any[] }; findings: RateFinding[] };
type Exposure = { source: string; score: number; severity: string; externalDependencies: number; behaviorDrift: number; rateDrift: number; reasons: string[] };
type Recommendation = { id: string; kind: string; namespace: string; workloadKind?: string; workloadName: string; confidence: string; rationale: string[]; manifest?: any };
type Remediation = { id: string; source: string; severity: string; kind: string; title: string; rationale: string[]; action: Record<string, any>; reviewRequired: boolean };

export default function Insights() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [drift, setDrift] = useState<Drift | null>(null);
  const [rateDrift, setRateDrift] = useState<RateDrift | null>(null);
  const [exposure, setExposure] = useState<Exposure[]>([]);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [rates, setRates] = useState<any>(null);
  const [ciliumEnabled, setCiliumEnabled] = useState(false);
  const [baseline, setBaseline] = useState<any>(null);
  const [rateBaseline, setRateBaseline] = useState<any>(null);
  const [window, setWindow] = useState('5m');
  const [msg, setMsg] = useState('');

  async function refresh() {
    try {
      const q = `?window=${encodeURIComponent(window)}`;
      const [s, g, d, rd, ex, r, rb, b, rem, rt] = await Promise.all([
        api<Summary>(`/api/v1/insights/summary${q}`),
        api<Graph>('/api/v1/insights/dependencies?limit=250'),
        api<Drift>('/api/v1/insights/drift'),
        api<RateDrift>(`/api/v1/insights/rate-drift${q}`),
        api<any>(`/api/v1/insights/exposure${q}`),
        api<any>('/api/v1/insights/recommendations?limit=30'),
        api<any>('/api/v1/insights/rate-baseline'),
        api<any>('/api/v1/insights/baseline'),
        api<any>(`/api/v1/insights/remediations${q}&limit=30`),
        api<any>(`/api/v1/insights/rates${q}`),
      ]);
      setSummary(s); setGraph(g); setDrift(d); setRateDrift(rd); setExposure(ex.items || []);
      setRecommendations(r.items || []); setCiliumEnabled(Boolean(r.ciliumEnabled)); setRateBaseline(rb); setBaseline(b);
      setRemediations(rem.items || []); setRates(rt); setMsg('');
    } catch (e) { setMsg(String(e)); }
  }
  useEffect(() => { void refresh(); }, [window]);

  const nodeByID = useMemo(() => new Map((graph?.nodes || []).map((n) => [n.id, n])), [graph]);
  const label = (id: string) => { const n = nodeByID.get(id); if (!n) return id; if (n.kind === 'external') return n.ip || n.name; return `${n.namespace || ''}/${n.name}`.replace(/^\//, ''); };

  async function captureBehavior() { try { const x = await api<any>('/api/v1/insights/baseline', { method: 'POST' }); setMsg(`Behavior baseline captured with ${x.baseline?.entries?.length || 0} entries.`); await refresh(); } catch (e) { setMsg(String(e)); } }
  async function clearBehavior() { if (!confirm('Clear the known-good behavior baseline?')) return; try { await api('/api/v1/insights/baseline', { method: 'DELETE', headers: { 'X-Netra-Confirm-Baseline-Clear': 'clear' } }); await refresh(); } catch (e) { setMsg(String(e)); } }
  async function captureRate() { try { const x = await api<any>(`/api/v1/insights/rate-baseline?window=${encodeURIComponent(window)}`, { method: 'POST' }); setMsg(`Rate baseline captured with ${x.baseline?.entries?.length || 0} entries.`); await refresh(); } catch (e) { setMsg(String(e)); } }
  async function clearRate() { if (!confirm('Clear the traffic-rate baseline?')) return; try { await api('/api/v1/insights/rate-baseline', { method: 'DELETE', headers: { 'X-Netra-Confirm-Rate-Baseline-Clear': 'clear' } }); await refresh(); } catch (e) { setMsg(String(e)); } }

  return <div className="grid">
    <section className="card span3">
      <p className="eyebrow">CONTROLS</p>
      <h3>Rate window and baselines</h3>
      <div className="toolbar"><label>Rate window <select value={window} onChange={e => setWindow(e.target.value)}><option>1m</option><option>5m</option><option>15m</option><option>30m</option><option>1h</option></select></label><button className="primary" onClick={refresh}>Refresh</button></div>
      {msg && <p className="warning">{msg}</p>}
      {summary?.rateWarming && <p className="warning">Rate engine is warming up. At least two fresh agent reports are required before rate drift is evaluated.</p>}
      <div className="metrics">
        <div><b>{summary?.dependencyEdges ?? '—'}</b><span>dependency edges</span></div>
        <div><b>{summary?.driftFindings ?? '—'}</b><span>behavior drift</span></div>
        <div><b>{summary?.rateDriftFindings ?? '—'}</b><span>rate anomalies</span></div>
        <div><b>{summary?.highExposure ?? '—'}</b><span>high exposure</span></div>
      </div>
    </section>

    <section className="card">
      <p className="eyebrow">KNOWN GOOD</p><h3>Behavior inventory</h3>
      <p>{baseline?.captured ? `Captured ${new Date(baseline.baseline?.capturedAt).toLocaleString()} · ${baseline.baseline?.entries?.length ?? 0} entries` : 'No behavior baseline captured.'}</p>
      <div className="toolbar"><button className="primary" onClick={captureBehavior}>{baseline?.captured ? 'Recapture' : 'Capture'}</button><button onClick={clearBehavior} disabled={!baseline?.captured}>Clear</button></div>
    </section>

    <section className="card">
      <p className="eyebrow">TRAFFIC RATE</p><h3>Window baseline</h3>
      <p>{rateBaseline?.captured ? `Captured ${new Date(rateBaseline.baseline?.capturedAt).toLocaleString()} · ${rateBaseline.baseline?.entries?.length ?? 0} metric rates` : 'No traffic-rate baseline captured.'}</p>
      <div className="toolbar"><button className="primary" onClick={captureRate} disabled={Boolean(rateDrift?.window?.warming)}>{rateBaseline?.captured ? 'Recapture' : 'Capture'}</button><button onClick={clearRate} disabled={!rateBaseline?.captured}>Clear</button></div>
    </section>

    <section className="card span2">
      <p className="eyebrow">RATE WINDOW</p><h3>Current deltas</h3>
      {rates?.warming && <p className="warning">Warming up — waiting for consecutive agent reports.</p>}
      <div className="list">{(rates?.metrics || []).slice(0, 12).map((m:any, i:number) => <div className="insightrow" key={`${m.source}-${m.metric}-${i}`}><b>{m.metric || m.name || 'rate'}</b><span>{m.source || m.workload || '—'}</span><small>{Number(m.rate ?? m.value ?? 0).toFixed(2)}/s</small></div>)}</div>
      {!rates?.warming && !(rates?.metrics || []).length && <p>No rate samples in this window yet.</p>}
    </section>

    <section className="card">
      <p className="eyebrow">EXPOSURE</p><h3>Highest-ranked workloads</h3>
      {(exposure || []).slice(0, 8).map(x => <div className={`insightrow ${x.severity}`} key={x.source}><b>{x.score}/100 · {x.severity}</b><span>{x.source}</span><small>{(x.reasons || []).join(' · ')}</small></div>)}
      {!exposure.length && <p>No exposure signals yet.</p>}
    </section>

    <section className="card span2">
      <p className="eyebrow">RATE DRIFT</p><h3>Time-window anomalies</h3>
      {!rateDrift?.baselineCapturedAt && <p>Capture a rate baseline after warm-up to compare current traffic rates.</p>}
      {(rateDrift?.findings || []).slice(0, 30).map((f, i) => <div className={`insightrow ${f.severity}`} key={`${f.source}-${f.metric}-${i}`}><b>{f.metric}</b><span>{f.source}</span><code>{f.ratio ? `${f.ratio.toFixed(1)}×` : 'new'}</code><small>{(f.currentRate ?? 0).toFixed(2)}/s current · {(f.baselineRate ?? 0).toFixed(2)}/s baseline</small></div>)}
      {rateDrift?.baselineCapturedAt && !(rateDrift.findings || []).length && !rateDrift.window?.warming && <p>No rate changes crossed the deterministic thresholds.</p>}
    </section>

    <section className="card">
      <p className="eyebrow">BEHAVIOR DRIFT</p><h3>New inventory</h3>
      {(drift?.findings || []).slice(0, 20).map((f, i) => <div className={`insightrow ${f.severity}`} key={`${f.source}-${f.kind}-${f.value}-${i}`}><b>{f.kind}</b><span>{f.source}</span><code>{f.value}</code></div>)}
      {drift?.baselineCapturedAt && !(drift.findings || []).length && <p>No new behavior crossed noise thresholds.</p>}
    </section>

    <section className="card span3">
      <p className="eyebrow">DEPENDENCY GRAPH</p><h3>Workload → workload/service/external</h3>
      <div className="flowhead deps"><span>SOURCE</span><span>TARGET</span><span>NETWORK</span><span>PACKETS / BYTES</span></div>
      {(graph?.edges || []).slice(0, 100).map((e, i) => <div className="flowrow deps" key={`${e.source}-${e.target}-${e.protocol}-${e.port}-${i}`}><span>{label(e.source)}</span><span>{label(e.target)} {e.external ? '↗' : ''}</span><span>{e.protocol}{e.port ? `/${e.port}` : ''}</span><span>{e.packets.toLocaleString()} / {e.bytes.toLocaleString()}</span></div>)}
    </section>

    <section className="card span3">
      <p className="eyebrow">REMEDIATION PROPOSALS</p><h3>Review-only containment and investigation drafts</h3>
      <p>Netra does not auto-execute these. A proposal is evidence plus a suggested next action, not authorization to block traffic.</p>
      <div className="recommendations">{remediations.map(r => <details key={r.id} className="recommendation"><summary><b>{r.title}</b><span>{r.severity} · {r.source}</span></summary>{r.rationale.map(x => <p key={x}>• {x}</p>)}<pre>{JSON.stringify(r.action, null, 2)}</pre></details>)}{!remediations.length && <p>No remediation draft currently meets the thresholds.</p>}</div>
    </section>

    <section className="card span3">
      <p className="eyebrow">POLICY RECOMMENDATIONS</p><h3>Observed-traffic CiliumNetworkPolicy drafts</h3>
      {!ciliumEnabled && <p className="warning">Cilium integration is disabled. Drafts remain export/review only.</p>}
      <div className="recommendations">{recommendations.map(r => <details key={r.id} className="recommendation"><summary><b>{r.namespace}/{r.workloadName}</b><span>{r.confidence} · {r.kind}</span></summary>{r.rationale.map(x => <p key={x}>• {x}</p>)}<pre>{JSON.stringify(r.manifest, null, 2)}</pre></details>)}</div>
    </section>
  </div>;
}
