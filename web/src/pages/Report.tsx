import { useEffect, useState } from 'react';
import { api } from '../api';

type Snapshot = {
  generatedAt: string;
  headline: string;
  mode: string;
  scopeMode?: string;
  agents: number;
  staleAgents: number;
  healthScore: number;
  packets: number;
  blocked: number;
  tcpRetransmissions: number;
  dnsFailures: number;
  anomalyCount: number;
  driftFindings: number;
  rateDriftFindings: number;
  highExposure: number;
  incidentClusters: number;
  attention?: string[];
  recentAudit?: string[];
};

type Step = {
  id: string;
  severity: string;
  title: string;
  rationale: string;
  command?: string;
  api?: string;
  autoApply: boolean;
  reviewOnly: boolean;
};

type Book = { headline: string; count: number; steps: Step[] };

type AuditSum = {
  total: number;
  byActor?: { key: string; count: number }[];
  byAction?: { key: string; count: number }[];
};

export default function Report() {
  const [snap, setSnap] = useState<Snapshot>();
  const [book, setBook] = useState<Book>();
  const [sum, setSum] = useState<AuditSum>();
  const [msg, setMsg] = useState('');

  const load = () => {
    Promise.all([
      api<Snapshot>('/api/v1/report?format=json'),
      api<Book>('/api/v1/playbooks'),
      api<AuditSum>('/api/v1/audit/summary'),
    ])
      .then(([s, b, a]) => {
        setSnap(s);
        setBook(b);
        setSum(a);
        setMsg('');
      })
      .catch((e) => setMsg(String(e)));
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">OPERATOR REPORT</p>
        <h3>{snap?.headline || 'Point-in-time briefing'}</h3>
        <p>Observe-only. This page never applies policy or extends an enforce lease.</p>
        {msg && <p className="warning">{msg}</p>}
        {snap && (
          <div className="list">
            <div className="agent wide">
              <b>Mode</b>
              <span>{snap.mode}</span>
              <small>{snap.scopeMode || 'scope n/a'}</small>
            </div>
            <div className="agent wide">
              <b>Health</b>
              <span>{snap.healthScore}/100</span>
              <small>
                {snap.agents} agents · {snap.staleAgents} stale
              </small>
            </div>
            <div className="agent wide">
              <b>Drift / exposure</b>
              <span>
                {snap.driftFindings} drift · {snap.rateDriftFindings} rate · {snap.highExposure} high exposure
              </span>
              <small>{snap.incidentClusters} incident clusters</small>
            </div>
          </div>
        )}
      </section>

      <section className="card span3">
        <p className="eyebrow">PLAYBOOK</p>
        <h3>Review-only next steps</h3>
        <p>Auto-apply is always off. Copy a command only after you agree with the rationale.</p>
        {!book?.steps?.length && <p className="empty-state">No playbook steps yet.</p>}
        <div className="list">
          {(book?.steps || []).map((s) => (
            <div className={`insightrow ${s.severity}`} key={s.id}>
              <b>{s.title}</b>
              <span className={`severity-badge ${s.severity}`}>{s.severity}</span>
              <small>{s.rationale}</small>
              {s.command && <small><code>{s.command}</code></small>}
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">ATTENTION</p>
        <h3>What the briefing called out</h3>
        {!(snap?.attention || []).length && <p className="empty-state">No attention items.</p>}
        <div className="list">
          {(snap?.attention || []).map((a, i) => (
            <div className="agent wide" key={i}>
              <small>{a}</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">AUDIT ROLLUP</p>
        <h3>{sum?.total ?? 0} events</h3>
        <div className="list">
          {(sum?.byActor || []).slice(0, 8).map((r) => (
            <div className="agent wide" key={r.key}>
              <b>{r.key}</b>
              <span>{r.count}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
