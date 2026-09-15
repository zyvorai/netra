import { useEffect, useState } from 'react';
import { api } from '../api';

type Card = {
  score?: number;
  band?: string;
  headline?: string;
  healthScore?: number;
  staleAgents?: number;
  detachedPrograms?: number;
  missingMaps?: number;
  blockedEvents?: number;
  notes?: string[];
};

export default function Scorecard() {
  const [card, setCard] = useState<Card>();
  const [err, setErr] = useState('');
  const load = () => {
    api<Card>('/api/v1/scorecard').then((c) => { setCard(c); setErr(''); }).catch((e) => setErr(String(e)));
  };
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);
  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">SCORECARD</p>
        <h3>{card?.score ?? '—'} · {card?.band || 'unknown'}</h3>
        <p>{card?.headline || 'Observe-only rollup of health, coverage, and blocked events.'}</p>
        {err && <p className="warning">{err}</p>}
        {card && (
          <div className="list">
            <div className="agent wide"><b>Health</b><span>{card.healthScore}</span></div>
            <div className="agent wide"><b>Stale agents</b><span>{card.staleAgents}</span></div>
            <div className="agent wide"><b>Detached programs</b><span>{card.detachedPrograms}</span></div>
            <div className="agent wide"><b>Missing maps</b><span>{card.missingMaps}</span></div>
            <div className="agent wide"><b>Blocked events</b><span>{card.blockedEvents}</span></div>
            {(card.notes || []).map((n) => <div className="agent wide" key={n}><b>Note</b><span>{n}</span></div>)}
          </div>
        )}
      </section>
    </div>
  );
}
