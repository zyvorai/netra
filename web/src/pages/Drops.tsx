import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import TerminalFrame from '../components/TerminalFrame';

export default function Drops(){
  const [data,setData]=useState<any>(); const [err,setErr]=useState('');
  const load=()=>api<any>('/api/v1/ebpf/drops?limit=100').then(x=>{setData(x);setErr('')}).catch(e=>setErr(String(e)));
  useEffect(()=>{load();const t=setInterval(load,5000);return()=>clearInterval(t)},[]);
  const s=data?.summary||{}; const nodes=useMemo(()=>data?.nodes||[],[data]); const anomalies=s.anomalies||[];
  return <div className="grid">
    <section className="card span3"><p className="eyebrow">DROP DIAGNOSTICS</p><h2>Find where packets disappear.</h2><p>Netra combines an optional eBPF <code>skb:kfree_skb</code> tracepoint with Linux softnet and interface counters. Kernel drop reasons are node-level because the tracepoint does not carry trustworthy pod/cgroup identity.</p>{err&&<p className="warning">{err}</p>}</section>
    <section className="card span3"><p className="eyebrow">DROP PULSE</p><div className="metrics">
      <div><b>{s.kernelDropEvents||0}</b><span>kernel skb drops</span></div>
      <div><b>{s.softnetDropped||0}</b><span>softnet dropped</span></div>
      <div><b>{s.softnetTimeSqueeze||0}</b><span>softnet time squeeze</span></div>
      <div><b>{s.rxDropped||0}</b><span>interface rx dropped</span></div>
      <div><b>{s.txDropped||0}</b><span>interface tx dropped</span></div>
      <div><b>{s.rxMissed||0}</b><span>rx missed</span></div>
      <div><b>{s.rxErrors||0}</b><span>rx errors</span></div>
      <div><b>{s.txErrors||0}</b><span>tx errors</span></div>
    </div></section>
    <section className="card span3"><p className="eyebrow">STACK SIGNALS</p><h3>Queue and interface findings</h3><div className="list">{anomalies.length===0&&<p>No drop-pressure thresholds triggered.</p>}{anomalies.map((a:any,i:number)=><div className="agent wide" key={i}><b>{a.kind}</b><span className={a.severity==='critical'?'blocked':''}>{a.severity}</span><span>{a.subject}</span><small>{a.message}</small></div>)}</div></section>
    {nodes.map((n:any)=><div className="span3" key={n.node}><TerminalFrame title={`kernel drops · ${n.node}`}><div className="flowhead obs"><span>REASON</span><span>PROTOCOL</span><span>COUNT</span><span>LAST NS</span></div>{(n.kernelDrops||[]).map((d:any,i:number)=><div className="flowrow obs" key={i}><span>reason #{d.reason}</span><span>{d.protocol||'unknown'}</span><span>{d.count}</span><span>{d.lastSeenNs||0}</span></div>)}{!(n.kernelDrops||[]).length&&<div className="flowrow"><span>No kfree_skb tracepoint data. The hook may be unavailable on this kernel.</span></div>}</TerminalFrame></div>)}
    {nodes.map((n:any)=><section className="card span3" key={`${n.node}-if`}><p className="eyebrow">NODE STACK · {n.node}</p><p>softnet processed {n.stack?.softnetProcessed||0} · dropped {n.stack?.softnetDropped||0} · time squeeze {n.stack?.softnetTimeSqueeze||0}</p><div className="list">{(n.stack?.interfaces||[]).map((it:any)=><div className="agent wide" key={it.name}><b>{it.name}</b><span>rx-drop {it.rxDropped}</span><span>tx-drop {it.txDropped}</span><small>rx-errors {it.rxErrors} · tx-errors {it.txErrors} · rx-missed {it.rxMissed} · no-handler {it.rxNoHandler}</small></div>)}</div></section>)}
  </div>
}
