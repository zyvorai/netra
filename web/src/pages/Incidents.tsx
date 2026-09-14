import { useEffect, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';

type Finding = { kind: string; severity: string; joinConfidence?: string; subject: string; message: string; at: string };
type Cluster = { generatedAt: string; sourceKey: string; subject: string; severity: string; findings: Finding[] };

const KIND_LABEL: Record<string, string> = {
  health: 'Health',
  drift: 'Behavior drift',
  'rate-drift': 'Rate drift',
  exposure: 'Exposure',
  detective: 'Drop detective',
  audit: 'Audit',
};

export default function Incidents() {
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [msg, setMsg] = useState('');

  const load = () => api<{ items: Cluster[]; count: number }>('/api/v1/incidents')
    .then((x) => { setClusters(x.items || []); setMsg(''); })
    .catch((e) => setMsg(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);

  return <div className="grid">
    <section className="card span3">
      <p className="eyebrow">INCIDENTS</p>
      <h3>Cross-signal correlation</h3>
      <p>Groups health anomalies, behavior/rate drift, exposure, drop-detective findings, and audit events that share a source — only shown once at least two different signal kinds agree on the same workload, pod, or node. A drop-detective or audit-event join is best-effort IP/name matching (marked <b>probable</b>); everything else matched exactly on its own source key.</p>
      {msg && <p className="warning">{msg}</p>}
      {!clusters.length && !msg && <p className="empty-state">No cross-signal incidents right now — single-signal findings are already visible on their own pages (Health, Insights, Drops, Audit).</p>}
    </section>

    {clusters.map((c) => (
      <section className="card span3" key={c.sourceKey}>
        <p className="eyebrow"><span className={`severity-badge ${c.severity}`}>{c.severity}</span></p>
        <h3 className="truncate" title={c.subject} aria-label={c.subject}>{c.subject}</h3>
        <p><small>{c.sourceKey}</small></p>
        <div className="list">
          {c.findings.map((f, i) => (
            <div className={`insightrow ${f.severity}`} key={i}>
              <b>{KIND_LABEL[f.kind] || f.kind}</b>
              <span>{f.joinConfidence ? `${f.joinConfidence} match` : ''}</span>
              <span className="truncate" title={new Date(f.at).toLocaleString()}>{new Date(f.at).toLocaleString()}</span>
              <small>{f.message}</small>
              <ExplainFinding page="incidents" kind={f.kind} subject={c.subject} message={f.message} severity={f.severity} />
            </div>
          ))}
        </div>
      </section>
    ))}
  </div>;
}
