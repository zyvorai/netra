import { useEffect, useState } from 'react';
import { api } from '../api';
import TerminalFrame from '../components/TerminalFrame';

export default function Overview() {
  const [data, setData] = useState<any>(undefined);
  const [pulse, setPulse] = useState<any>(undefined);
  const [err, setErr] = useState('');
  useEffect(() => {
    Promise.all([
      api('/api/v1/status'),
      api('/api/v1/flows/summary?number=500&direction=EGRESS'),
    ]).then(([status, summary]) => {
      setData(status);
      setPulse(summary);
    }).catch((e) => setErr(String(e)));
  }, []);
  const fp = data?.fastPath;
  const dropped = pulse?.verdicts?.DROPPED ?? 0;
  const forwarded = pulse?.verdicts?.FORWARDED ?? 0;
  return (
    <div className="grid">
      <section className="card span2">
        <p className="eyebrow">CONTROL PLANE</p>
        <h2>Netra {data?.version || '—'}</h2>
        <div className="metrics">
          <div><b>{data?.agents ?? 0}</b><span>eBPF agents</span></div>
          <div><b>{data?.staleAgents ?? 0}</b><span>stale agents</span></div>
          <div><b>{fp?.mode || '—'}</b><span>fast-path mode</span></div>
          <div><b>{data?.hubbleError ? 'degraded' : 'online'}</b><span>Hubble Relay</span></div>
          <div><b>{data?.haEnabled ? 'leader' : 'single'}</b><span>{data?.haEnabled ? (data?.controllerIdentity || 'HA controller') : 'controller mode'}</span></div>
        </div>
        {data?.requirePreflight && <p>Policy apply guard: <b>server-enforced preflight receipt required</b>.</p>}
        {fp?.enforceUntil && <p className="warning">Enforcement lease expires {new Date(fp.enforceUntil).toLocaleString()}.</p>}
        {(data?.staleAgents ?? 0) > 0 && <p className="warning">One or more eBPF agents have stopped reporting. Enforcement still fails open locally on lease/controller timeout.</p>}
      </section>
      <TerminalFrame title="hubble-relay / status"><pre>{err || JSON.stringify(data?.hubble ?? { state: 'loading' }, null, 2)}</pre></TerminalFrame>
      <section className="card span2">
        <p className="eyebrow">HUBBLE FLOW PULSE</p>
        <h3>Latest {pulse?.total ?? 0} egress flows</h3>
        <div className="metrics">
          <div><b>{forwarded}</b><span>forwarded</span></div>
          <div><b>{dropped}</b><span>dropped</span></div>
          <div><b>{pulse?.protocols?.TCP ?? 0}</b><span>TCP</span></div>
          <div><b>{pulse?.protocols?.UDP ?? 0}</b><span>UDP</span></div>
        </div>
        {(pulse?.dropReasons || []).slice(0, 3).map((x: any) => <p key={x.name}><b>{x.name}</b> · {x.count} drop(s)</p>)}
      </section>
      <TerminalFrame title="top egress destinations"><pre>{JSON.stringify(pulse?.topDestinations ?? [], null, 2)}</pre></TerminalFrame>
      <section className="card"><h3>Boundary by design</h3><p>Cilium stays authoritative for identity, routing and policy. Hubble supplies flow/verdict data. Netra eBPF owns only its own pinned maps and emergency exact-IP control.</p></section>
    </div>
  );
}
