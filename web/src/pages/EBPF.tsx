import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import TerminalFrame from '../components/TerminalFrame';

export default function EBPF() {
  const [cfg, setCfg] = useState<any>();
  const [agents, setAgents] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>();
  const [caps, setCaps] = useState<any>();
  const [err, setErr] = useState('');
  const [lease, setLease] = useState('15m');
  const [ip, setIP] = useState('');
  const [cidr, setCIDR] = useState('');
  const [cidrDir, setCIDRDir] = useState('egress');
  const [port, setPort] = useState('443');
  const [proto, setProto] = useState('TCP');
  const [portDir, setPortDir] = useState('egress');
  const [uid, setUID] = useState('');
  const [dns, setDNS] = useState('');
  const [processName, setProcessName] = useState('');
  const [rateIP, setRateIP] = useState('');
  const [pps, setPPS] = useState('1000');
  const [eventType, setEventType] = useState('all');
  const [workloads, setWorkloads] = useState<any[]>([]);
  const [scopeNS, setScopeNS] = useState('');
  const [scopePod, setScopePod] = useState('');
  const [scopeKind, setScopeKind] = useState('');
  const [scopeWorkload, setScopeWorkload] = useState('');
  const [scopeLabel, setScopeLabel] = useState('');
  const [scopePreview, setScopePreview] = useState<any>();
  const [topology, setTopology] = useState<any[]>([]);

  const load = () => Promise.all([
    api<any>('/api/v1/ebpf/config'),
    api<any>('/api/v1/agents'),
    api<any>('/api/v1/ebpf/summary'),
    api<any>('/api/v1/ebpf/capabilities'),
    api<any>('/api/v1/ebpf/workloads'),
    api<any>('/api/v1/ebpf/topology?limit=50'),
  ]).then(([c, a, s, k, w, t]) => {
    setCfg(c); setAgents(a.items || []); setSummary(s); setCaps(k); setWorkloads(w.items || []); setTopology(t.items || []); setErr('');
  }).catch(e => setErr(String(e)));

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  async function call(path: string, method: string, body?: any) {
    try {
      await api(path, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
      await load();
    } catch (e) { setErr(String(e)); }
  }

  async function mode(m: string) {
    if (m === 'enforce' && !confirm(`Enable standalone eBPF enforcement for ${lease}? It automatically returns to observe mode when the lease or controller failsafe expires.`)) return;
    await call(`/api/v1/ebpf/mode${m === 'enforce' ? `?lease=${encodeURIComponent(lease)}` : ''}`, 'PUT', { mode: m });
  }

  function candidateScope() {
    const labels: Record<string,string> = {};
    if (scopeLabel.trim()) {
      const [k, ...rest] = scopeLabel.split('=');
      if (!k || !rest.length) throw new Error('Label selector must be key=value');
      labels[k.trim()] = rest.join('=').trim();
    }
    const scope: any = { namespace: scopeNS.trim(), pod: scopePod.trim(), workloadKind: scopeKind.trim(), workloadName: scopeWorkload.trim(), labels };
    if (!scope.namespace && !scope.pod && !scope.workloadKind && !scope.workloadName && !Object.keys(labels).length) throw new Error('Choose at least one workload selector');
    return scope;
  }
  async function applyScope(selected: boolean) {
    if (!selected) return call('/api/v1/ebpf/scope', 'PUT', { mode: 'all', scopes: [] });
    try { await call('/api/v1/ebpf/scope', 'PUT', { mode: 'selected', scopes: [candidateScope()] }); } catch (e) { setErr(String(e)); }
  }
  async function previewScope() {
    try { setScopePreview(await api('/api/v1/ebpf/scope/preview', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ scopes:[candidateScope()] }) })); setErr(''); } catch (e) { setErr(String(e)); }
  }

  const events = useMemo(() => agents
    .flatMap(a => (a.events || []).map((e: any) => ({ ...e, node: a.node })))
    .sort((a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt))
    .filter((e: any) => eventType === 'all' || e.type === eventType)
    .slice(0, 220), [agents, eventType]);
  const stats = useMemo(() => agents
    .flatMap(a => (a.stats || []).map((s: any) => ({ ...s, node: a.node })))
    .sort((a, b) => (b.packets || 0) - (a.packets || 0)).slice(0, 160), [agents]);

  return <div className="grid">
    <section className="card span3"><p className="eyebrow">ENFORCEMENT LEASE</p><h3>Observe or time-boxed enforce</h3><p>No Cilium dependency. Blocking requires an explicit lease. Netra owns only <code>/sys/fs/bpf/netra</code>.</p><div className="toolbar"><button className={cfg?.mode === 'observe' ? 'primary' : ''} onClick={() => mode('observe')}>Observe</button><input value={lease} onChange={e => setLease(e.target.value)} title="1m–24h"/><button className={cfg?.mode === 'enforce' ? 'danger' : ''} onClick={() => mode('enforce')}>Enforce lease</button></div>{cfg?.enforceUntil && <p className="warning">Lease expires: {new Date(cfg.enforceUntil).toLocaleString()}</p>}{err && <p className="warning">{err}</p>}</section>

    <section className="card span3"><p className="eyebrow">WORKLOAD SCOPE</p><h3>Observe the node. Enforce only the workloads you choose.</h3><p>In <b>selected</b> mode, blocking runs only on cgroup/socket hooks whose cgroup resolves to a matching Kubernetes pod. TCX/XDP remain observation-only because they do not carry a reliable workload cgroup identity.</p><div className="ruleform"><input value={scopeNS} onChange={e => setScopeNS(e.target.value)} placeholder="namespace, e.g. payments"/><input value={scopePod} onChange={e => setScopePod(e.target.value)} placeholder="pod (optional)"/><input value={scopeKind} onChange={e => setScopeKind(e.target.value)} placeholder="owner kind, e.g. ReplicaSet"/><input value={scopeWorkload} onChange={e => setScopeWorkload(e.target.value)} placeholder="owner name (optional)"/><input value={scopeLabel} onChange={e => setScopeLabel(e.target.value)} placeholder="label key=value (optional)"/><button onClick={previewScope}>Preview</button><button className={cfg?.scopeMode !== 'selected' ? 'primary' : ''} onClick={() => applyScope(false)}>All cgroups</button><button className={cfg?.scopeMode === 'selected' ? 'danger' : ''} onClick={() => applyScope(true)}>Selected workloads</button></div>{scopePreview && <p><b>{scopePreview.count}</b> of {scopePreview.totalPods} pods match this preview.</p>}<p className={cfg?.scopeMode === 'selected' ? 'warning' : ''}>Current: <b>{cfg?.scopeMode || 'all'}</b> · {(cfg?.workloadScopes || []).length} configured scope(s) · {workloads.length} pods discovered.</p><div className="chips">{(cfg?.workloadScopes || []).map((x:any, i:number) => <span key={i}>{x.namespace || '*'} / {x.pod || x.workloadName || '*'} {x.labels && Object.keys(x.labels).length ? JSON.stringify(x.labels) : ''}</span>)}</div></section>

    <section className="card"><p className="eyebrow">EXACT IP</p><h3>IPv4 + IPv6 egress deny</h3><div className="toolbar"><input value={ip} onChange={e => setIP(e.target.value)} placeholder="203.0.113.10 or 2001:db8::1"/><button className="primary" onClick={() => call('/api/v1/ebpf/deny', 'POST', { ip })}>Add</button></div><div className="chips">{[...(cfg?.blockedIPv4 || []), ...(cfg?.blockedIPv6 || [])].map((x: string) => <button key={x} onClick={() => call('/api/v1/ebpf/deny/' + encodeURIComponent(x), 'DELETE')}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">CIDR</p><h3>Ingress / egress prefixes</h3><div className="ruleform"><input value={cidr} onChange={e => setCIDR(e.target.value)} placeholder="10.0.0.0/8 or 2001:db8::/32"/><select value={cidrDir} onChange={e => setCIDRDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/cidr', 'POST', { cidr, direction: cidrDir })}>Add CIDR</button></div><div className="chips">{(cfg?.blockedCidrs || []).map((x: any) => <button key={x.cidr + x.direction} onClick={() => call('/api/v1/ebpf/cidr/delete', 'POST', x)}>{x.direction} · {x.cidr} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">L4</p><h3>Port controls</h3><div className="ruleform"><select value={proto} onChange={e => setProto(e.target.value)}><option>TCP</option><option>UDP</option><option>ANY</option></select><input value={port} onChange={e => setPort(e.target.value)} inputMode="numeric"/><select value={portDir} onChange={e => setPortDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/port', 'POST', { protocol: proto, port: Number(port), direction: portDir })}>Add port</button></div><div className="chips">{(cfg?.blockedPorts || []).map((x: any) => <button key={x.protocol + x.port + x.direction} onClick={() => call('/api/v1/ebpf/port/delete', 'POST', x)}>{x.direction} · {x.protocol}/{x.port} ×</button>)}</div></section>

    <section className="card"><p className="eyebrow">IDENTITY</p><h3>UID socket deny</h3><p>Blocks new TCP connects and UDP sendmsg operations from a Linux UID while enforcement is leased.</p><div className="toolbar"><input value={uid} onChange={e => setUID(e.target.value)} inputMode="numeric" placeholder="1000"/><button className="primary" onClick={() => call('/api/v1/ebpf/uid', 'POST', { uid: Number(uid) })}>Add UID</button></div><div className="chips">{(cfg?.blockedUids || []).map((x: number) => <button key={x} onClick={() => call('/api/v1/ebpf/uid/' + x, 'DELETE')}>uid {x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">PROCESS</p><h3>Linux comm deny</h3><p>Blocks new connect/sendmsg operations by exact process <code>comm</code> (maximum 15 bytes). Existing sockets are not terminated.</p><div className="toolbar"><input value={processName} onChange={e => setProcessName(e.target.value)} placeholder="curl" maxLength={15}/><button className="primary" onClick={() => call('/api/v1/ebpf/process', 'POST', { name: processName })}>Add process</button></div><div className="chips">{(cfg?.blockedProcesses || []).map((x: string) => <button key={x} onClick={() => call('/api/v1/ebpf/process/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">DNS</p><h3>Exact DNS-name deny</h3><p>Parses and blocks exact cleartext DNS queries over UDP/53. This does not inspect TCP DNS, DoT, or DoH.</p><div className="toolbar"><input value={dns} onChange={e => setDNS(e.target.value)} placeholder="telemetry.example.com"/><button className="primary" onClick={() => call('/api/v1/ebpf/dns', 'POST', { name: dns })}>Add DNS</button></div><div className="chips">{(cfg?.blockedDns || []).map((x: string) => <button key={x} onClick={() => call('/api/v1/ebpf/dns/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>

    <section className="card"><p className="eyebrow">RATE CONTROL</p><h3>Destination PPS ceiling</h3><p>Simple fixed-window IPv4 destination packet-rate guard. Intended as an emergency containment control, not QoS.</p><div className="ruleform"><input value={rateIP} onChange={e => setRateIP(e.target.value)} placeholder="203.0.113.20"/><input value={pps} onChange={e => setPPS(e.target.value)} inputMode="numeric"/><button className="primary" onClick={() => call('/api/v1/ebpf/rate', 'PUT', { destination: rateIP, pps: Number(pps) })}>Set PPS</button></div><div className="chips">{(cfg?.rateLimits || []).map((x: any) => <button key={x.destination} onClick={() => call('/api/v1/ebpf/rate/' + encodeURIComponent(x.destination), 'DELETE')}>{x.destination} · {x.pps}pps ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">KERNEL PULSE</p><h3>What Netra sees</h3><div className="metrics"><div><b>{summary?.packets ?? 0}</b><span>packets</span></div><div><b>{summary?.blocked ?? 0}</b><span>blocked</span></div><div><b>{summary?.dnsQueries ?? 0}</b><span>DNS</span></div><div><b>{summary?.socketEvents ?? 0}</b><span>socket events</span></div></div><pre className="mini">{JSON.stringify({ hooks: summary?.hooks, reasons: summary?.blockReasons, topDNS: summary?.topDns, topProcesses: summary?.topProcesses, topWorkloads: summary?.topWorkloads, blockedWorkloads: summary?.topBlockedWorkloads }, null, 2)}</pre></section>
    <section className="card span3"><p className="eyebrow">BPF PROGRAM HEALTH</p><h3>Attach state and run stats</h3><p>Per-node program attach flags plus kernel run counts when BPF stats are enabled. Use this when a hook is missing after upgrade or verifier load failures.</p>{agents.map(a => <div className="agent wide" key={'prog-'+a.node}><b>{a.node}</b><span>{a.stale ? 'stale' : `${(a.programs || []).filter((p:any)=>p.attached).length}/${(a.programs || []).length} attached`}</span><small>{(a.programs || []).length === 0 ? 'no program report yet' : (a.programs || []).map((p:any) => `${p.name}${p.attached ? '' : ' (detached)'}: runs=${p.runCount || 0}`).join(' · ')}</small></div>)}</section>
    <section className="card span3"><p className="eyebrow">NETWORK HISTOGRAMS</p><h3>Retransmit / RTT / connect buckets</h3><p>Agent-side histograms from existing sockops samples, plus listen overflow and softirq NET_RX counters. Softirq entry→exit latency remains deferred.</p>{agents.map(a => {
      const h = a.histograms;
      if (!h) return <div className="agent wide" key={'hist-'+a.node}><b>{a.node}</b><span>—</span></div>;
      return <div className="agent wide" key={'hist-'+a.node}><b>{a.node}</b><span>retrans n={h.tcpRetransmissions?.count || 0} · srtt n={h.tcpSrttUs?.count || 0} · connect n={h.tcpConnectUs?.count || 0}</span><small>listen overflows={h.host?.listenOverflows || 0} · listen drops={h.host?.listenDrops || 0} · softirq NET_RX={h.host?.softirqNetRx || 0}</small></div>;
    })}</section>
    <section className="card"><p className="eyebrow">CAPABILITIES</p><h3>No Cilium required</h3><p>{caps?.observability?.length || 0} observability classes and {caps?.enforcement?.length || 0} enforcement classes are exposed by this release.</p><div className="chips">{(caps?.hooks || []).map((x: string) => <span key={x}>{x}</span>)}</div></section>

    <div className="span3"><TerminalFrame title="standalone eBPF events"><div className="eventtools"><span>Recent flow, DNS, socket and block events</span><select value={eventType} onChange={e => setEventType(e.target.value)}><option value="all">all</option><option value="flow">flow</option><option value="dns">dns</option><option value="connect">connect</option><option value="block">block</option></select></div><div className="flowhead obs"><span>TIME / NODE</span><span>TYPE</span><span>PROCESS</span><span>FLOW / DNS</span><span>ACTION</span></div>{events.map((e: any, i) => <div className="flowrow obs" key={i}><span>{new Date(e.observedAt).toLocaleTimeString()} · {e.node}</span><span>{e.direction} {e.hook} · {e.type}</span><span>{e.namespace || e.pod ? `${e.namespace}/${e.pod} · ${e.comm || 'process?'} pid=${e.pid || 0}` : (e.comm ? `${e.comm} pid=${e.pid} uid=${e.uid}` : '—')}</span><span>{e.dnsQuery || `${e.sourceIp || '—'}:${e.sourcePort || 0} → ${e.destinationIp || '—'}:${e.destinationPort || 0} ${e.protocol}`}</span><span className={e.action === 'blocked' ? 'blocked' : ''}>{e.action}{e.reason ? ` · ${e.reason}` : ''}</span></div>)}</TerminalFrame></div>
    <div className="span3"><TerminalFrame title="exact flow counters"><div className="flowhead obs"><span>NODE / HOOK</span><span>DIR</span><span>FLOW</span><span>PROTO</span><span>PACKETS / BYTES / BLOCKED</span></div>{stats.map((s: any, i) => <div className="flowrow obs" key={i}><span>{s.node} · {s.hook}{s.namespace ? ` · ${s.namespace}/${s.pod}` : ''}</span><span>{s.direction}</span><span>{s.sourceIp || '—'}:{s.sourcePort || 0} → {s.destinationIp}:{s.port}</span><span>{s.protocol}</span><span>{s.packets} / {s.bytes} / {s.blocked}</span></div>)}</TerminalFrame></div>
    <div className="span3"><TerminalFrame title="workload network topology"><div className="flowhead obs"><span>WORKLOAD</span><span>NODE</span><span>DESTINATION</span><span>PROTO</span><span>PACKETS / BYTES / BLOCKED</span></div>{topology.map((e:any, i:number) => <div className="flowrow obs" key={i}><span>{e.namespace}/{e.pod}{e.workloadName ? ` · ${e.workloadKind}/${e.workloadName}` : ''}</span><span>{e.node}</span><span>{e.destination}</span><span>{e.protocol}</span><span>{e.packets} / {e.bytes} / {e.blocked}</span></div>)}</TerminalFrame></div>
    <section className="card span3"><p className="eyebrow">NODE COVERAGE</p><h3>Attached hooks</h3>{agents.map(a => <div className="agent wide" key={a.node}><b>{a.node}</b><span>{a.stale ? 'stale' : a.mode}</span><span>{(a.hooks || []).join(', ') || '—'}</span><small>{(a.workloads || []).length} workload cgroups · {a.scopeMode || 'all'} scope ({a.selectedCgroups || 0} selected) · {a.cgroupPath || 'no cgroup'} · interfaces: {(a.interfaces || []).join(', ') || 'cgroup-only'} · XDP: {(a.xdpInterfaces || []).join(', ') || 'off'}</small></div>)}</section>
  </div>;
}
