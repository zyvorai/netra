import { useEffect, useRef, useState } from 'react';
import { api, authHeaders } from '../api';
import TerminalFrame from '../components/TerminalFrame';
import { endpointName, tuple } from '../lib/flow';

export default function Flows() {
  const [flows, setFlows] = useState<any[]>([]);
  const [drops, setDrops] = useState<any[]>([]);
  const [dropError, setDropError] = useState('');
  const [filter, setFilter] = useState({ direction: 'EGRESS', verdict: '', protocol: '', namespace: '', pod: '', destination: '' });
  const [run, setRun] = useState(0);
  const ctrl = useRef<AbortController | undefined>(undefined);

  useEffect(() => {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    const q = new URLSearchParams({ number: '100', ...Object.fromEntries(Object.entries(filter).filter(([, v]) => v)) });
    (async () => {
      try {
        const r = await fetch('/api/v1/flows/stream?' + q, { headers: authHeaders(), signal: c.signal });
        if (!r.ok) throw new Error(await r.text());
        if (!r.body) return;
        const rd = r.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        while (true) {
          const res = await rd.read();
          if (res.done) break;
          buf += dec.decode(res.value, { stream: true });
          let i;
          while ((i = buf.indexOf('\n\n')) >= 0) {
            const part = buf.slice(0, i);
            buf = buf.slice(i + 2);
            const line = part.split('\n').find((v: string) => v.startsWith('data: '));
            if (line && part.includes('event: flow')) {
              const f = JSON.parse(line.slice(6));
              setFlows((old) => [f, ...old].slice(0, 250));
            }
          }
        }
      } catch (e: any) {
        if (e.name !== 'AbortError') console.error(e);
      }
    })();
    return () => c.abort();
  }, [run]);

  async function explainDrops() {
    try {
      const q = new URLSearchParams();
      if (filter.namespace) q.set('namespace', filter.namespace);
      if (filter.pod) q.set('pod', filter.pod);
      q.set('limit', '20');
      const x = await api<any>('/api/v1/drops/explain?' + q);
      setDrops(x.items || []);
      setDropError('');
    } catch (e) {
      setDropError(String(e));
    }
  }

  return (
    <div className="grid">
      <section className="card span2">
        <p className="eyebrow">HUBBLE RELAY</p>
        <h2>Live flows</h2><p>Optional Cilium/Hubble enrichment. When Hubble is disabled, use <b>eBPF Network</b> for Netra-native flow, DNS, process and block telemetry.</p>
        <div className="filters">
          {Object.entries(filter).map(([k, v]) => (
            <label key={k}>{k}<input value={v} placeholder={k === 'direction' ? 'EGRESS' : ''} onChange={(e) => setFilter({ ...filter, [k]: e.target.value })} /></label>
          ))}
          <button className="primary" onClick={() => { setFlows([]); setRun((x) => x + 1); }}>Reconnect</button>
          <button onClick={explainDrops}>Explain recent drops</button>
        </div>
      </section>
      <div className="span3">
        <TerminalFrame title="observer.GetFlows / filtered">
          <div className="flowhead"><span>VERDICT</span><span>DIR</span><span>SOURCE → DESTINATION</span><span>NETWORK</span></div>
          {flows.map((f, i) => <div className="flowrow" key={i}><span>{f.verdict}</span><span>{f.trafficDirection}</span><span>{endpointName(f.source)} → {endpointName(f.destination)}</span><span>{tuple(f)}</span></div>)}
        </TerminalFrame>
      </div>
      <section className="card span3">
        <p className="eyebrow">DROP EXPLAIN</p>
        <h3>Recent Hubble denials</h3>
        {dropError && <p className="warning">{dropError}</p>}
        {drops.length === 0 && <p>Use “Explain recent drops” to fetch recent denied flows for the current namespace/pod scope.</p>}
        {drops.map((d, i) => (
          <div className="dropcard" key={i}>
            <b>{d.summary || 'Dropped flow'}</b>
            <span>{d.dropReason || 'unknown reason'}</span>
            {(d.suggestions || []).map((s: string) => <p key={s}>• {s}</p>)}
          </div>
        ))}
      </section>
    </div>
  );
}
