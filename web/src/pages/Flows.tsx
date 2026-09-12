import { useEffect, useRef, useState } from 'react';
import { api, authHeaders } from '../api';
import TerminalFrame from '../components/TerminalFrame';
import { endpointName, tuple } from '../lib/flow';

type Filter = {
  direction: string;
  verdict: string;
  protocol: string;
  namespace: string;
  pod: string;
  destination: string;
};

export default function Flows() {
  const [flows, setFlows] = useState<any[]>([]);
  const [drops, setDrops] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>();
  const [summaryError, setSummaryError] = useState('');
  const [dropError, setDropError] = useState('');
  const [filter, setFilter] = useState<Filter>({
    direction: 'EGRESS',
    verdict: '',
    protocol: '',
    namespace: '',
    pod: '',
    destination: '',
  });
  const [run, setRun] = useState(0);
  const ctrl = useRef<AbortController | undefined>(undefined);

  async function loadSummary(f: Filter = filter) {
    try {
      const q = new URLSearchParams({
        number: '500',
        ...Object.fromEntries(Object.entries(f).filter(([, v]) => v)),
      });
      const x = await api<any>('/api/v1/flows/summary?' + q);
      setSummary(x);
      setSummaryError('');
    } catch (e) {
      setSummaryError(String(e));
    }
  }

  useEffect(() => {
    void loadSummary(filter);
  }, [run]);

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

  const verdicts = summary?.verdicts || {};
  const protocols = summary?.protocols || {};

  return (
    <div className="grid">
      <section className="card span2">
        <p className="eyebrow">LIVE STREAM</p>
        <h3>Filters</h3>
        <p>
          Optional Cilium/Hubble enrichment. When Hubble is disabled, use <b>eBPF</b>, <b>Network Health</b>, and{' '}
          <b>L7 Metadata</b> for Netra-native telemetry.
        </p>
        <div className="filters">
          {Object.entries(filter).map(([k, v]) => (
            <label key={k}>
              {k}
              <input
                value={v}
                placeholder={k === 'direction' ? 'EGRESS' : ''}
                onChange={(e) => setFilter({ ...filter, [k]: e.target.value })}
              />
            </label>
          ))}
          <button
            className="btn-refresh"
            onClick={() => {
              setFlows([]);
              setRun((x) => x + 1);
            }}
          >
            Reconnect
          </button>
          <button className="btn-refresh" onClick={() => void loadSummary()}>Refresh summary</button>
          <button className="btn-diag" onClick={explainDrops}>Explain recent drops</button>
        </div>
      </section>

      <section className="card">
        <p className="eyebrow">FLOW SUMMARY</p>
        <h3>Window aggregate</h3>
        {summaryError && <p className="warning">{summaryError}</p>}
        <div className="metrics">
          <div>
            <b>{summary?.total ?? 0}</b>
            <span>flows sampled</span>
          </div>
          <div>
            <b>{verdicts.FORWARDED ?? 0}</b>
            <span>forwarded</span>
          </div>
          <div>
            <b>{verdicts.DROPPED ?? 0}</b>
            <span>dropped</span>
          </div>
          <div>
            <b>{(protocols.TCP ?? 0) + (protocols.UDP ?? 0)}</b>
            <span>TCP+UDP</span>
          </div>
        </div>
        {(summary?.dropReasons || []).slice(0, 4).map((x: any) => (
          <p key={x.name}>
            <b>{x.name}</b> · {x.count}
          </p>
        ))}
      </section>

      <div className="span3">
        <TerminalFrame title="observer.GetFlows / filtered">
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

      <section className="card span2">
        <p className="eyebrow">TOP DESTINATIONS</p>
        <h3>From summary window</h3>
        <div className="list">
          {(summary?.topDestinations || []).length === 0 && <p>No destination aggregate yet — reconnect or refresh summary.</p>}
          {(summary?.topDestinations || []).map((x: any) => (
            <button key={x.name} type="button" onClick={() => setFilter({ ...filter, destination: x.name })}>
              <span>
                <b>{x.name}</b>
              </span>
              <span>{x.count}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="card">
        <p className="eyebrow">PROTOCOLS</p>
        <h3>Sample mix</h3>
        <div className="chips">
          {Object.entries(protocols).map(([name, count]) => (
            <span key={name}>
              {name} · {String(count)}
            </span>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">DROP EXPLAIN</p>
        <h3>Recent Hubble denials</h3>
        {dropError && <p className="warning">{dropError}</p>}
        {drops.length === 0 && (
          <p>Use “Explain recent drops” to fetch recent denied flows for the current namespace/pod scope.</p>
        )}
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
    </div>
  );
}
