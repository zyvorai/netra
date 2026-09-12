import { useEffect, useState } from 'react';
import { api } from '../api';

export default function Audit() {
  const [items, setItems] = useState<any[]>([]);
  useEffect(() => {
    api<any>('/api/v1/audit?limit=200').then((x) => setItems(x.items || []));
  }, []);
  return (
    <div className="grid">
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
    </div>
  );
}
