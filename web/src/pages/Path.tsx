import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';

const ms = (us:number|undefined) => ((us||0)/1000).toFixed((us||0)>=100000?0:1);
const pct = (n:number,d:number) => d ? `${(n*100/d).toFixed(0)}%` : '0%';

export default function Path(){
  const [data,setData]=useState<any>(); const [err,setErr]=useState('');
  const load=()=>api<any>('/api/v1/ebpf/path?limit=100').then(x=>{setData(x);setErr('')}).catch(e=>setErr(String(e)));
  useEffect(()=>{load();const t=setInterval(load,5000);return()=>clearInterval(t)},[]);
  const s=data?.summary||{}; const anomalies=s.anomalies||[];
  const pressure=useMemo(()=>data?.pressure||[],[data]); const connect=useMemo(()=>data?.connect||[],[data]);
  return <div className="grid">
    {err&&<section className="card span3"><p className="warning">{err}</p></section>}
    <section className="card span3"><p className="eyebrow">PATH PULSE</p><div className="metrics">
      <div><b>{s.connectionsMeasured||0}</b><span>connects timed</span></div>
      <div><b>{ms(s.averageConnectUs)} ms</b><span>avg connect</span></div>
      <div><b>{ms(s.maxConnectUs)} ms</b><span>max connect</span></div>
      <div><b>{s.congestedFlows||0}</b><span>cwnd-pressure flows</span></div>
      <div><b>{s.retransOut||0}</b><span>retrans out</span></div>
      <div><b>{s.lostOut||0}</b><span>lost out</span></div>
      <div><b>{s.packetsOut||0}</b><span>packets in flight</span></div>
      <div><b>{s.deliveredRatePps||0}</b><span>delivered pkt/s samples</span></div>
    </div></section>
    <section className="card span3"><p className="eyebrow">PATH SIGNALS</p><h3>Transport-pressure findings</h3><p>Threshold-based diagnostics only. Netra does not infer router/interface drop reasons from these counters.</p><div className="list">{anomalies.length===0&&<p className="empty-state">No current path-pressure thresholds triggered.</p>}{anomalies.slice(0,25).map((a:any,i:number)=><div className="agent wide" key={i}><b>{a.kind}</b><span className={`severity-badge ${a.severity}`}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small><ExplainFinding page="path" kind={a.kind} subject={a.subject} message={a.message} severity={a.severity} /></div>)}{anomalies.length>25&&<p className="empty-state">+{anomalies.length-25} more not shown.</p>}</div></section>
    <section className="card span3">
      <p className="eyebrow">TCP PRESSURE</p><h3>Exact sockops transport state</h3>
      {pressure.length===0 && <p className="empty-state">No TCP pressure samples yet.</p>}
      {pressure.length>0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>CWND / FLIGHT</span><span>LOSS</span><span>DELIVERY</span></div>
        {pressure.map((p:any,i:number)=>{
          const who = p.namespace?`${p.namespace}/${p.pod}`:`cgroup ${p.cgroupId||0}`;
          return <div className="datarow obs" key={i}><span className="truncate" title={who} aria-label={who}>{who}</span><span>{p.remoteIp}:{p.remotePort}</span><span>{p.packetsOut}/{p.sendCwnd} · {pct(p.packetsOut,p.sendCwnd)}</span><span>lost {p.lostOut} · retrans-out {p.retransOut} · total {p.totalRetrans}</span><span>{p.rateIntervalUs?Math.round(p.rateDelivered*1000000/p.rateIntervalUs):0} pkt/s · MSS {p.mss||0}</span></div>;
        })}
      </div>}
    </section>
    <section className="card span3">
      <p className="eyebrow">TCP CONNECT</p><h3>Establishment latency</h3>
      {connect.length===0 && <p className="empty-state">No TCP connect samples yet.</p>}
      {connect.length>0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>REMOTE</span><span>ESTABLISHED</span><span>AVG</span><span>MAX</span></div>
        {connect.map((c:any,i:number)=>{
          const who = c.namespace?`${c.namespace}/${c.pod}`:`cgroup ${c.cgroupId||0}`;
          return <div className="datarow obs" key={i}><span className="truncate" title={who} aria-label={who}>{who}</span><span>{c.remoteIp}:{c.remotePort}</span><span>{c.established}</span><span>{ms(c.established?c.totalLatencyUs/c.established:0)} ms</span><span>{ms(c.maxLatencyUs)} ms</span></div>;
        })}
      </div>}
    </section>
  </div>
}
