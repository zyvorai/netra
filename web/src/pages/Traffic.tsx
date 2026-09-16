import { useEffect, useState } from 'react';
import { api } from '../api';
import { protoNameClass } from '../lib/flow';

type NSRow = { namespace: string; packets: number; bytes: number; blocked: number; destinations: number };
type ProtoRow = { protocol: string; packets: number; bytes: number; blocked: number; flows: number };
type PortRow = { port: number; protocol: string; key: string; packets: number; blocked: number; flows: number };
type DNSRow = { name: string; queries: number; responses: number; failures: number; failRate: number };

export default function Traffic() {
  const [ns, setNs] = useState<{ rows?: NSRow[] }>();
  const [proto, setProto] = useState<{ rows?: ProtoRow[] }>();
  const [ports, setPorts] = useState<{ rows?: PortRow[] }>();
  const [dns, setDns] = useState<{ rows?: DNSRow[]; queries?: number; failures?: number }>();
  const [err, setErr] = useState('');
  const load = () => Promise.all([
    api<{ rows?: NSRow[] }>('/api/v1/namespaces/heat'),
    api<{ rows?: ProtoRow[] }>('/api/v1/protocols'),
    api<{ rows?: PortRow[] }>('/api/v1/ports'),
    api<{ rows?: DNSRow[]; queries?: number; failures?: number }>('/api/v1/dns/board'),
  ]).then(([n, p, po, d]) => { setNs(n); setProto(p); setPorts(po); setDns(d); setErr(''); }).catch((e) => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 20000); return () => clearInterval(t); }, []);

  return (
    <div className="grid">
      {err && <section className="card span3"><p className="warning">{err}</p></section>}

      <section className="card span3">
        <p className="eyebrow">NAMESPACE HEAT</p>
        <h3>Traffic by Kubernetes namespace</h3>
        <p>Packets/bytes/blocked rolled up by namespace from current agent destination stats.</p>
        <div className="list">
          {(ns?.rows || []).length === 0 && <p className="empty-state">No namespace traffic observed yet.</p>}
          {(ns?.rows || []).map((r) => (
            <div className={`agent wide${r.blocked ? ' row-blocked' : ''}`} key={r.namespace}>
              <b>{r.namespace}</b><span>{r.packets} pkts</span><small>{r.destinations} destinations · {r.blocked} blocked</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">PROTOCOL MIX</p>
        <h3>L4 protocol breakdown</h3>
        <p>Protocol mix across current destination stats.</p>
        <div className="list">
          {(proto?.rows || []).length === 0 && <p className="empty-state">No protocol data yet.</p>}
          {(proto?.rows || []).map((r) => (
            <div className={`agent wide${r.blocked ? ' row-blocked' : ''}`} key={r.protocol}>
              <b className={protoNameClass(r.protocol)}>{r.protocol}</b><span>{r.packets} pkts</span><small>{r.flows} flows · {r.blocked} blocked</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">PORT HEAT</p>
        <h3>Top destination ports</h3>
        <p>Top destination ports by packet count.</p>
        <div className="list">
          {(ports?.rows || []).length === 0 && <p className="empty-state">No port data yet.</p>}
          {(ports?.rows || []).map((r) => (
            <div className={`agent wide${r.blocked ? ' row-blocked' : ''}`} key={r.key}>
              <b><span className={protoNameClass(r.protocol)}>{r.protocol}</span>/{r.port}</b><span>{r.packets} pkts</span><small>{r.flows} flows · {r.blocked} blocked</small>
            </div>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">DNS BOARD</p>
        <h3>{dns?.queries ?? 0} queries · {dns?.failures ?? 0} failures</h3>
        <p>DNS names ranked by failure count from agent DNS health stats.</p>
        <div className="list">
          {(dns?.rows || []).length === 0 && <p className="empty-state">No DNS activity observed yet.</p>}
          {(dns?.rows || []).map((r) => (
            <div className={`agent wide${r.failures ? ' row-blocked' : ''}`} key={r.name}>
              <b>{r.name}</b><span>{(r.failRate * 100).toFixed(1)}% fail</span><small>{r.queries} queries · {r.failures} failures</small>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
