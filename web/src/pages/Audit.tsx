import { useEffect, useState } from 'react';
import { api } from '../api';
import BlockedEvents from '../components/BlockedEvents';

export default function Audit() {
  const [items, setItems] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any>();
  useEffect(() => {
    api<any>('/api/v1/audit?limit=200').then((x) => setItems(x.items || []));
    api<any>('/api/v1/incidents/timeline').then(setTimeline).catch(() => {});
  }, []);
  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">INCIDENT TIMELINE</p>
        <h3>What happened, in order</h3>
        <p>Merges the audit log with cluster-health-signature transitions into plain sentences — never raw counters.</p>
        {timeline?.prose && <p>{timeline.prose}</p>}
        <div className="list">
          {(timeline?.entries || []).length === 0 && <p className="empty-state">No timeline entries yet.</p>}
          {(timeline?.entries || []).slice(0, 100).map((e: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{e.kind === 'digest-transition' ? 'health change' : 'action'}</b>
              <span>{new Date(e.at).toLocaleString()}</span>
              <small>{e.text}</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">CONTROL PLANE</p>
        <h3>Netra control-plane audit</h3>
        {items.length === 0 && <p className="empty-state">No audit events recorded yet.</p>}
        {items.length > 0 && (
          <div className="datatable-scroll">
            <div className="datahead audit">
              <span>TIME</span>
              <span>ACTOR</span>
              <span>ACTION</span>
              <span>TARGET</span>
            </div>
            {items.map((x, i) => (
              <div className="datarow audit" key={i}>
                <span>{new Date(x.at).toLocaleString()}</span>
                <span className="truncate" title={x.actor} aria-label={x.actor}>{x.actor}</span>
                <span>{x.action}</span>
                <span className="truncate" title={x.target || '—'} aria-label={x.target || '—'}>{x.target || '—'}</span>
              </div>
            ))}
          </div>
        )}
      </section>
      <BlockedEvents />
    </div>
  );
}
