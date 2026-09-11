import { useEffect, useRef, useState } from 'react';
import { api, authHeaders } from '../api';
import TerminalFrame from './TerminalFrame';
import { endpointName, tuple } from '../lib/flow';

export type FlowFilter = {
  direction: string;
  verdict: string;
  protocol: string;
  namespace: string;
  pod: string;
  destination: string;
};

type Props = {
  title?: string;
  initial?: Partial<FlowFilter>;
  lockedScope?: boolean;
  showFilters?: boolean;
};

export default function LiveFlowTerminal({
  title = 'observer.GetFlows / filtered',
  initial,
  lockedScope = false,
  showFilters = true,
}: Props) {
  const [flows, setFlows] = useState<any[]>([]);
  const [drops, setDrops] = useState<any[]>([]);
  const [dropError, setDropError] = useState('');
  const [summary, setSummary] = useState<any>(null);
  const [filter, setFilter] = useState<FlowFilter>({
    direction: 'EGRESS',
    verdict: '',
    protocol: '',
    namespace: '',
    pod: '',
    destination: '',
    ...initial,
  });
  const [run, setRun] = useState(0);
  const ctrl = useRef<AbortController | undefined>(undefined);

  useEffect(() => {
    setFilter((f) => ({ ...f, ...initial }));
    setFlows([]);
    setRun((x) => x + 1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial?.namespace, initial?.pod]);

  useEffect(() => {
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    const q = new URLSearchParams({
      number: '100',
      ...Object.fromEntries(Object.entries(filter).filter(([, v]) => v)),
    });
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

  async function loadSummary() {
    try {
      const q = new URLSearchParams({ number: '500', direction: filter.direction || 'EGRESS' });
      if (filter.namespace) q.set('namespace', filter.namespace);
      if (filter.pod) q.set('pod', filter.pod);
      if (filter.verdict) q.set('verdict', filter.verdict);
      const x = await api<any>('/api/v1/flows/summary?' + q);
      setSummary(x);
    } catch {
      setSummary(null);
    }
  }

  useEffect(() => {
    if (filter.namespace || filter.pod) void loadSummary();
  }, [run]);

  return (
    <div className="grid" style={{ margin: 0 }}>
      {showFilters && (
        <section className="card span3">
          <div className="filters">
            {Object.entries(filter).map(([k, v]) => (
              <label key={k}>
                {k}
                <input
                  value={v}
                  disabled={lockedScope && (k === 'namespace' || k === 'pod')}
                  placeholder={k === 'direction' ? 'EGRESS' : ''}
                  onChange={(e) => setFilter({ ...filter, [k]: e.target.value })}
                />
              </label>
            ))}
            <button
              className="primary"
              onClick={() => {
                setFlows([]);
                setRun((x) => x + 1);
              }}
            >
              Reconnect
            </button>
            <button onClick={explainDrops}>Explain recent drops</button>
            <button onClick={loadSummary}>Refresh pulse</button>
          </div>
        </section>
      )}
      {!showFilters && (
        <div className="toolbar" style={{ marginBottom: 12 }}>
          <button
            className="primary"
            onClick={() => {
              setFlows([]);
              setRun((x) => x + 1);
            }}
          >
            Reconnect
          </button>
          <button onClick={explainDrops}>Explain drops</button>
          <button onClick={loadSummary}>Refresh pulse</button>
        </div>
      )}
      {summary && (
        <section className="card span3">
          <p className="eyebrow">PULSE</p>
          <h3>Top destinations</h3>
          <div className="chips">
            {(summary.topDestinations || []).slice(0, 8).map((d: any) => (
              <span key={d.name} className="buttonlike" style={{ cursor: 'default' }}>
                {d.name} · {d.count}
              </span>
            ))}
            {!(summary.topDestinations || []).length && <p>No recent destinations in scope.</p>}
          </div>
        </section>
      )}
      <div className="span3">
        <TerminalFrame title={title}>
          <div className="flowhead">
            <span>VERDICT</span>
            <span>DIR</span>
            <span>SOURCE → DESTINATION</span>
            <span>NETWORK</span>
          </div>
          {flows.map((f, i) => (
            <div className="flowrow" key={i}>
              <span>{f.verdict}</span>
              <span>{f.trafficDirection}</span>
              <span>
                {endpointName(f.source)} → {endpointName(f.destination)}
              </span>
              <span>{tuple(f)}</span>
            </div>
          ))}
        </TerminalFrame>
      </div>
      {(drops.length > 0 || dropError) && (
        <section className="card span3">
          <p className="eyebrow">DROP EXPLAIN</p>
          <h3>Recent Hubble denials</h3>
          {dropError && <p className="warning">{dropError}</p>}
          {drops.map((d, i) => (
            <div className="dropcard" key={i}>
              <b>{d.summary || 'Dropped flow'}</b>
              <span>{d.dropReason || 'unknown reason'}</span>
              {(d.suggestions || []).map((s: string) => (
                <p key={s}>• {s}</p>
              ))}
            </div>
          ))}
        </section>
      )}
    </div>
  );
}
