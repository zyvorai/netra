import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';

export default function Drops() {
  const [data, setData] = useState<any>();
  const [diag, setDiag] = useState<any>();
  const [err, setErr] = useState('');
  const load = () =>
    Promise.all([api<any>('/api/v1/ebpf/drops?limit=100'), api<any>('/api/v1/ebpf/diagnose?limit=50')])
      .then(([d, x]) => {
        setData(d);
        setDiag(x);
        setErr('');
      })
      .catch((e) => setErr(String(e)));
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);
  const s = data?.summary || {};
  const nodes = useMemo(() => data?.nodes || [], [data]);
  const anomalies = s.anomalies || [];
  const findings = diag?.findings || [];
  const ds = diag?.summary || {};
  return (
    <div className="grid">
      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}
      <section className="card span3">
        <p className="eyebrow">DROP PULSE</p>
        <div className="metrics">
          <div>
            <b>{s.kernelDropEvents || 0}</b>
            <span>kernel skb drops</span>
          </div>
          <div>
            <b>{s.softnetDropped || 0}</b>
            <span>softnet dropped</span>
          </div>
          <div>
            <b>{ds.policyDropPackets || 0}</b>
            <span>policy-drop packets</span>
          </div>
          <div>
            <b>{ds.conntrackEntries || 0}</b>
            <span>conntrack entries</span>
          </div>
          <div>
            <b>{ds.exactFindings || 0}</b>
            <span>exact findings</span>
          </div>
          <div>
            <b>{ds.probableFindings || 0}</b>
            <span>probable findings</span>
          </div>
          <div>
            <b>{s.rxDropped || 0}</b>
            <span>interface rx dropped</span>
          </div>
          <div>
            <b>{s.txDropped || 0}</b>
            <span>interface tx dropped</span>
          </div>
        </div>
        <p>{ds.text || ''}</p>
      </section>
      <section className="card span3">
        <p className="eyebrow">DROP DETECTIVE</p>
        <h3>Policy-aware findings</h3>
        <div className="list">
          {findings.length === 0 && <p className="empty-state">No Netra policy-drop findings.</p>}
          {findings.map((f: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{f.code}</b>
              <span className={f.confidence === 'exact' ? 'blocked' : ''}>{f.confidence}</span>
              <span>
                {f.src} → {f.dst}
              </span>
              <small>
                {f.explanation} {f.suggestion}
              </small>
            </div>
          ))}
        </div>
      </section>
      <section className="card span3">
        <p className="eyebrow">STACK SIGNALS</p>
        <h3>Queue and interface findings</h3>
        <div className="list">
          {anomalies.length === 0 && <p className="empty-state">No drop-pressure thresholds triggered.</p>}
          {anomalies.map((a: any, i: number) => (
            <div className="agent wide" key={i}>
              <b>{a.kind}</b>
              <span className={`severity-badge ${a.severity}`}>{a.severity}</span>
              <span>{a.subject}</span>
              <small>{a.message}</small>
            </div>
          ))}
        </div>
      </section>
      {nodes.map((n: any) => (
        <section className="card span3" key={n.node}>
          <p className="eyebrow">KERNEL DROPS</p>
          <h3>{n.node}</h3>
          {!(n.kernelDrops || []).length && (
            <p className="empty-state">No kfree_skb tracepoint data. The hook may be unavailable on this kernel.</p>
          )}
          {(n.kernelDrops || []).length > 0 && (
            <div className="datatable-scroll">
              <div className="datahead">
                <span>REASON</span>
                <span>PROTOCOL</span>
                <span>COUNT</span>
                <span>LAST NS</span>
              </div>
              {(n.kernelDrops || []).map((d: any, i: number) => (
                <div className="datarow" key={i}>
                  <span>reason #{d.reason}</span>
                  <span>{d.protocol || 'unknown'}</span>
                  <span>{d.count}</span>
                  <span>{d.lastSeenNs || 0}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      ))}
      {nodes.map((n: any) => (
        <section className="card span3" key={`${n.node}-if`}>
          <p className="eyebrow">NODE STACK · {n.node}</p>
          <p>
            softnet processed {n.stack?.softnetProcessed || 0} · dropped {n.stack?.softnetDropped || 0} · time squeeze{' '}
            {n.stack?.softnetTimeSqueeze || 0}
          </p>
          <div className="list">
            {(n.stack?.interfaces || []).map((it: any) => (
              <div className="agent wide" key={it.name}>
                <b>{it.name}</b>
                <span>rx-drop {it.rxDropped}</span>
                <span>tx-drop {it.txDropped}</span>
                <small>
                  rx-errors {it.rxErrors} · tx-errors {it.txErrors} · rx-missed {it.rxMissed} · no-handler{' '}
                  {it.rxNoHandler}
                </small>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
