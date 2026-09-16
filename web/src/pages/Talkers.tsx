import { useEffect, useState } from 'react';
import { api } from '../api';

type Row = { destination?: string; packets?: number; bytes?: number; blocked?: number; nodes?: number };
type Board = { rows?: Row[]; count?: number };

export default function Talkers() {
  const [board, setBoard] = useState<Board>();
  const [err, setErr] = useState('');
  const load = () => {
    api<Board>('/api/v1/talkers?limit=30').then((b) => { setBoard(b); setErr(''); }).catch((e) => setErr(String(e)));
  };
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);
  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">TALKERS</p>
        <h3>Top destinations</h3>
        <p>Packet counts from current agent reports. Observe-only, no payloads.</p>
        {err && <p className="warning">{err}</p>}
        <div className="list">
          {(board?.rows || []).length === 0 && <p className="empty-state">No talkers observed yet.</p>}
          {(board?.rows || []).map((r) => (
            <div className={`agent wide${r.blocked ? ' row-blocked' : ''}`} key={r.destination}>
              <b>{r.destination}</b>
              <span>{r.packets} pkts</span>
              <small>{r.blocked || 0} blocked · {r.nodes || 0} nodes</small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
