import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import TerminalFrame from '../components/TerminalFrame';

type UnifiedRule = { id?: string; type: string; value: string; detail: string; extra: string; created?: string; raw?: any; del?: () => void };

// Fields relevant to each rule type, used to build both the inline edit
// form and the PATCH body — mirrors the shape internal/api/server.go's
// ebpfRulePatch expects per type.
const EDIT_FIELDS: Record<string, string[]> = {
  ip4: ['ip'], ip6: ['ip'],
  cidr: ['cidr', 'direction'],
  port: ['protocol', 'port', 'direction'],
  uid: ['uid'],
  dns: ['name'], sni: ['name'], process: ['name'],
  rate: ['destination', 'pps'],
};

export default function EBPF() {
  const [cfg, setCfg] = useState<any>();
  const [agents, setAgents] = useState<any[]>([]);
  const [caps, setCaps] = useState<any>();
  const [shieldDiag, setShieldDiag] = useState<any>();
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
  const [sni, setSNI] = useState('');
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
  const [shieldMode, setShieldMode] = useState('off');
  const [shieldProtectAll, setShieldProtectAll] = useState(false);
  const [shieldSyn, setShieldSyn] = useState('0');
  const [shieldUdp, setShieldUdp] = useState('0');
  const [shieldIcmp, setShieldIcmp] = useState('0');
  const [shieldOther, setShieldOther] = useState('0');
  const [shieldBurst, setShieldBurst] = useState('2');
  const [shieldIP, setShieldIP] = useState('');
  const [ruleList, setRuleList] = useState<any[]>([]);
  const [editingId, setEditingId] = useState('');
  const [editForm, setEditForm] = useState<Record<string, string>>({});
  const [historyId, setHistoryId] = useState('');
  const [history, setHistory] = useState<any[]>([]);

  const load = () => Promise.all([
    api<any>('/api/v1/ebpf/config'),
    api<any>('/api/v1/agents'),
    api<any>('/api/v1/ebpf/capabilities'),
    api<any>('/api/v1/ebpf/workloads'),
    api<any>('/api/v1/ebpf/topology?limit=50'),
    api<any>('/api/v1/ebpf/shield?limit=1'),
    api<any>('/api/v1/ebpf/rules'),
  ]).then(([c, a, k, w, t, sd, rl]) => {
    setCfg(c); setAgents(a.items || []); setCaps(k); setWorkloads(w.items || []); setTopology(t.items || []); setShieldDiag(sd); setRuleList(rl.items || []); setErr('');
  }).catch(e => setErr(String(e)));

  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  // Sync the shield form from server state only when the server's config
  // actually changed (generation bump), not on every 5s poll — otherwise
  // an in-progress edit would get stomped before the user hits Apply.
  useEffect(() => {
    if (!cfg?.shield) return;
    setShieldMode(cfg.shield.mode || 'off');
    setShieldProtectAll(!!cfg.shield.protectAll);
    setShieldSyn(String(cfg.shield.synPps || 0));
    setShieldUdp(String(cfg.shield.udpPps || 0));
    setShieldIcmp(String(cfg.shield.icmpPps || 0));
    setShieldOther(String(cfg.shield.otherPps || 0));
    setShieldBurst(String(cfg.shield.burstSeconds || 0));
  }, [cfg?.shield?.generation]);

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

  function shieldBody(overrides: any = {}) {
    return {
      mode: shieldMode, protectAll: shieldProtectAll, protectedIpv4: cfg?.shield?.protectedIpv4 || [],
      synPps: Number(shieldSyn) || 0, udpPps: Number(shieldUdp) || 0, icmpPps: Number(shieldIcmp) || 0,
      otherPps: Number(shieldOther) || 0, burstSeconds: Number(shieldBurst) || 0, ...overrides,
    };
  }
  async function applyShield() {
    if (shieldMode === 'enforce' && !confirm('Enable Shield enforce mode? This will drop traffic exceeding configured PPS thresholds for protected IPs.')) return;
    await call('/api/v1/ebpf/shield', 'PUT', shieldBody());
  }
  function addShieldIP() {
    if (!shieldIP.trim()) return;
    const ips = Array.from(new Set([...(cfg?.shield?.protectedIpv4 || []), shieldIP.trim()]));
    call('/api/v1/ebpf/shield', 'PUT', shieldBody({ protectedIpv4: ips }));
    setShieldIP('');
  }
  function delShieldIP(x: string) {
    call('/api/v1/ebpf/shield', 'PUT', shieldBody({ protectedIpv4: (cfg?.shield?.protectedIpv4 || []).filter((y: string) => y !== x) }));
  }
  function toggleNetPol() {
    const next = !cfg?.netPolEnabled;
    if (next && !confirm('Enabling NetPol enforcement may block previously-allowed traffic for workloads without matching allow rules.')) return;
    call('/api/v1/ebpf/netpol/config', 'PUT', { enabled: next });
  }

  function startEdit(r: any) {
    setHistoryId('');
    setEditingId(r.id);
    setEditForm({
      ip: r.value || '', name: r.value || '', uid: r.value || '',
      cidr: r.cidr || '', direction: r.direction || 'egress', protocol: r.protocol || 'TCP',
      port: r.port ? String(r.port) : '', destination: r.destination || '', pps: r.pps ? String(r.pps) : '',
    });
  }
  function cancelEdit() { setEditingId(''); }
  async function saveEdit(type: string) {
    const body: any = {};
    for (const f of EDIT_FIELDS[type] || []) {
      body[f] = (f === 'port' || f === 'pps' || f === 'uid') ? Number(editForm[f]) : editForm[f];
    }
    try {
      await api(`/api/v1/ebpf/rules/${encodeURIComponent(editingId)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      setEditingId('');
      await load();
    } catch (e) { setErr(String(e)); }
  }
  async function toggleHistory(id: string) {
    if (historyId === id) { setHistoryId(''); return; }
    setEditingId('');
    setHistoryId(id);
    try { setHistory((await api<any>(`/api/v1/ebpf/rules/${encodeURIComponent(id)}/history`)).items || []); } catch (e) { setErr(String(e)); }
  }
  async function rollback(id: string, revision: number) {
    if (!confirm('Undo this edit? This restores the value it had before this revision.')) return;
    try {
      await api(`/api/v1/ebpf/rules/${encodeURIComponent(id)}/rollback/${revision}`, { method: 'POST' });
      setHistory((await api<any>(`/api/v1/ebpf/rules/${encodeURIComponent(id)}/history`)).items || []);
      await load();
    } catch (e) { setErr(String(e)); }
  }

  const events = useMemo(() => agents
    .flatMap(a => (a.events || []).map((e: any) => ({ ...e, node: a.node })))
    .sort((a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt))
    .filter((e: any) => eventType === 'all' || e.type === eventType)
    .slice(0, 220), [agents, eventType]);
  const stats = useMemo(() => agents
    .flatMap(a => (a.stats || []).map((s: any) => ({ ...s, node: a.node })))
    .sort((a, b) => (b.packets || 0) - (a.packets || 0)).slice(0, 160), [agents]);

  const rules = useMemo<UnifiedRule[]>(() => {
    const out: UnifiedRule[] = ruleList.map((r: any) => ({
      id: r.id, type: r.type, raw: r,
      value: r.type === 'cidr' ? r.cidr : r.type === 'port' ? `${r.protocol}/${r.port}` : r.type === 'rate' ? r.destination : r.value,
      detail: r.direction || '', extra: r.type === 'rate' ? `${r.pps}pps` : '',
      created: r.createdBy ? `${r.createdBy} · ${new Date(r.createdAt).toLocaleString()}` : '',
      del: () => { if (confirm(`Delete this ${r.type} rule?`)) call('/api/v1/ebpf/rules/' + encodeURIComponent(r.id), 'DELETE'); },
    }));
    if (cfg?.shield?.mode && cfg.shield.mode !== 'off') out.push({ type: 'shield', value: cfg.shield.protectAll ? 'all traffic' : `${(cfg.shield.protectedIpv4 || []).length} protected IPs`, detail: cfg.shield.mode, extra: '' });
    if (cfg?.netPolEnabled) out.push({ type: 'netpol', value: `${(cfg.netPolDenies || []).length} deny entries`, detail: 'enabled', extra: '' });
    return out.sort((a, b) => a.type === b.type ? a.value.localeCompare(b.value) : a.type.localeCompare(b.type));
  }, [ruleList, cfg?.shield, cfg?.netPolEnabled, cfg?.netPolDenies]);

  function cap(count: number, limit: number | undefined) {
    if (!limit) return null;
    return <p className={count / limit > 0.9 ? 'warning' : ''}>{count} / {limit} rules</p>;
  }

  return <div className="grid">
    <div className="span3"><TerminalFrame title="all configured rules">
      <div className="flowhead rules"><span>TYPE</span><span>VALUE</span><span>DETAIL</span><span>CREATED</span><span>ACTIONS</span></div>
      {rules.length === 0 && <p style={{ padding: '9px 4px' }}>No firewall rules configured.</p>}
      {rules.map((r, i) => (
        <div key={r.id || (r.type + r.value + i)}>
          <div className="flowrow rules">
            <span>{r.type}</span><span>{r.value}</span><span>{r.detail}{r.extra}</span><span>{r.created || '—'}</span>
            <span>
              {r.id && <button onClick={() => startEdit(r.raw)}>edit</button>}
              {r.id && <button onClick={() => toggleHistory(r.id!)}>history</button>}
              {r.del && <button onClick={r.del}>delete</button>}
            </span>
          </div>
          {editingId === r.id && <div className="flowrow rules">
            <div style={{ gridColumn: '1 / -1' }} className="ruleform">
              {(EDIT_FIELDS[r.type] || []).map(f => {
                if (f === 'direction') return <select key={f} value={editForm.direction} onChange={e => setEditForm({ ...editForm, direction: e.target.value })}><option>egress</option><option>ingress</option><option>both</option></select>;
                if (f === 'protocol') return <select key={f} value={editForm.protocol} onChange={e => setEditForm({ ...editForm, protocol: e.target.value })}><option>TCP</option><option>UDP</option><option>ANY</option></select>;
                return <input key={f} value={editForm[f] || ''} onChange={e => setEditForm({ ...editForm, [f]: e.target.value })} placeholder={f} inputMode={(f === 'port' || f === 'pps' || f === 'uid') ? 'numeric' : undefined} />;
              })}
              <button className="primary" onClick={() => saveEdit(r.type)}>Save</button>
              <button onClick={cancelEdit}>Cancel</button>
            </div>
          </div>}
          {historyId === r.id && <div className="flowrow rules">
            <div style={{ gridColumn: '1 / -1' }}>
              {history.length === 0 && <p>No edit history for this rule.</p>}
              {history.map((h: any) => (
                <div key={h.id} className="agent wide">
                  <b>{new Date(h.at).toLocaleString()}</b><span>{h.actor}</span>
                  <small>{JSON.stringify(h.before)} → {JSON.stringify(h.after)}</small>
                  <button onClick={() => rollback(r.id!, h.id)}>undo this edit</button>
                </div>
              ))}
            </div>
          </div>}
        </div>
      ))}
    </TerminalFrame></div>

    <section className="card span3"><p className="eyebrow">ENFORCEMENT LEASE</p><h3>Observe or time-boxed enforce</h3><p>Blocking requires an explicit lease. Netra owns only <code>/sys/fs/bpf/netra</code>.</p><div className="toolbar"><button className={cfg?.mode === 'observe' ? 'primary' : ''} onClick={() => mode('observe')}>Observe</button><input value={lease} onChange={e => setLease(e.target.value)} title="1m–24h"/><button className={cfg?.mode === 'enforce' ? 'danger' : ''} onClick={() => mode('enforce')}>Enforce lease</button></div>{cfg?.enforceUntil && <p className="warning">Lease expires: {new Date(cfg.enforceUntil).toLocaleString()}</p>}{err && <p className="warning">{err}</p>}</section>

    <section className="card span3"><p className="eyebrow">WORKLOAD SCOPE</p><h3>Observe the node. Enforce only the workloads you choose.</h3><p>In <b>selected</b> mode, blocking runs only on cgroup/socket hooks whose cgroup resolves to a matching Kubernetes pod. TCX/XDP remain observation-only because they do not carry a reliable workload cgroup identity.</p><div className="ruleform"><input value={scopeNS} onChange={e => setScopeNS(e.target.value)} placeholder="namespace, e.g. payments"/><input value={scopePod} onChange={e => setScopePod(e.target.value)} placeholder="pod (optional)"/><input value={scopeKind} onChange={e => setScopeKind(e.target.value)} placeholder="owner kind, e.g. ReplicaSet"/><input value={scopeWorkload} onChange={e => setScopeWorkload(e.target.value)} placeholder="owner name (optional)"/><input value={scopeLabel} onChange={e => setScopeLabel(e.target.value)} placeholder="label key=value (optional)"/><button onClick={previewScope}>Preview</button><button className={cfg?.scopeMode !== 'selected' ? 'primary' : ''} onClick={() => applyScope(false)}>All cgroups</button><button className={cfg?.scopeMode === 'selected' ? 'danger' : ''} onClick={() => applyScope(true)}>Selected workloads</button></div>{scopePreview && <p><b>{scopePreview.count}</b> of {scopePreview.totalPods} pods match this preview.</p>}<p className={cfg?.scopeMode === 'selected' ? 'warning' : ''}>Current: <b>{cfg?.scopeMode || 'all'}</b> · {(cfg?.workloadScopes || []).length} configured scope(s) · {workloads.length} pods discovered.</p><div className="chips">{(cfg?.workloadScopes || []).map((x:any, i:number) => <span key={i}>{x.namespace || '*'} / {x.pod || x.workloadName || '*'} {x.labels && Object.keys(x.labels).length ? JSON.stringify(x.labels) : ''}</span>)}</div></section>

    <section className="card"><p className="eyebrow">EXACT IP</p><h3>IPv4 + IPv6 egress deny</h3>{cap((cfg?.blockedIPv4?.length||0), caps?.limits?.exactIPv4)}<div className="toolbar"><input value={ip} onChange={e => setIP(e.target.value)} placeholder="203.0.113.10 or 2001:db8::1"/><button className="primary" onClick={() => call('/api/v1/ebpf/deny', 'POST', { ip })}>Add</button></div><div className="chips">{[...(cfg?.blockedIPv4 || []), ...(cfg?.blockedIPv6 || [])].map((x: string) => <button key={x} onClick={() => call('/api/v1/ebpf/deny/' + encodeURIComponent(x), 'DELETE')}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">CIDR</p><h3>Ingress / egress prefixes</h3>{cap((cfg?.blockedCidrs?.length||0), caps?.limits?.cidr)}<div className="ruleform"><input value={cidr} onChange={e => setCIDR(e.target.value)} placeholder="10.0.0.0/8 or 2001:db8::/32"/><select value={cidrDir} onChange={e => setCIDRDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/cidr', 'POST', { cidr, direction: cidrDir })}>Add CIDR</button></div><div className="chips">{(cfg?.blockedCidrs || []).map((x: any) => <button key={x.cidr + x.direction} onClick={() => call('/api/v1/ebpf/cidr/delete', 'POST', x)}>{x.direction} · {x.cidr} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">L4</p><h3>Port controls</h3>{cap((cfg?.blockedPorts?.length||0), caps?.limits?.ports)}<div className="ruleform"><select value={proto} onChange={e => setProto(e.target.value)}><option>TCP</option><option>UDP</option><option>ANY</option></select><input value={port} onChange={e => setPort(e.target.value)} inputMode="numeric"/><select value={portDir} onChange={e => setPortDir(e.target.value)}><option>egress</option><option>ingress</option><option>both</option></select><button className="primary" onClick={() => call('/api/v1/ebpf/port', 'POST', { protocol: proto, port: Number(port), direction: portDir })}>Add port</button></div><div className="chips">{(cfg?.blockedPorts || []).map((x: any) => <button key={x.protocol + x.port + x.direction} onClick={() => call('/api/v1/ebpf/port/delete', 'POST', x)}>{x.direction} · {x.protocol}/{x.port} ×</button>)}</div></section>

    <section className="card"><p className="eyebrow">IDENTITY</p><h3>UID socket deny</h3><p>Blocks new TCP connects and UDP sendmsg operations from a Linux UID while enforcement is leased.</p>{cap((cfg?.blockedUids?.length||0), caps?.limits?.uids)}<div className="toolbar"><input value={uid} onChange={e => setUID(e.target.value)} inputMode="numeric" placeholder="1000"/><button className="primary" onClick={() => call('/api/v1/ebpf/uid', 'POST', { uid: Number(uid) })}>Add UID</button></div><div className="chips">{(cfg?.blockedUids || []).map((x: number) => <button key={x} onClick={() => call('/api/v1/ebpf/uid/' + x, 'DELETE')}>uid {x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">PROCESS</p><h3>Linux comm deny</h3><p>Blocks new connect/sendmsg operations by exact process <code>comm</code> (maximum 15 bytes). Existing sockets are not terminated.</p>{cap((cfg?.blockedProcesses?.length||0), caps?.limits?.processes)}<div className="toolbar"><input value={processName} onChange={e => setProcessName(e.target.value)} placeholder="curl" maxLength={15}/><button className="primary" onClick={() => call('/api/v1/ebpf/process', 'POST', { name: processName })}>Add process</button></div><div className="chips">{(cfg?.blockedProcesses || []).map((x: string) => <button key={x} onClick={() => call('/api/v1/ebpf/process/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">DNS</p><h3>Exact DNS-name deny</h3><p>Parses and blocks exact cleartext DNS queries over UDP/53. This does not inspect TCP DNS, DoT, or DoH.</p>{cap((cfg?.blockedDns?.length||0), caps?.limits?.dns)}<div className="toolbar"><input value={dns} onChange={e => setDNS(e.target.value)} placeholder="telemetry.example.com"/><button className="primary" onClick={() => call('/api/v1/ebpf/dns', 'POST', { name: dns })}>Add DNS</button></div><div className="chips">{(cfg?.blockedDns || []).map((x: string) => <button key={x} onClick={() => call('/api/v1/ebpf/dns/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>
    <section className="card"><p className="eyebrow">SNI</p><h3>Exact TLS SNI deny</h3><p>Blocks connections whose TLS ClientHello Server Name Indication matches exactly. Best-effort parsing only.</p>{cap((cfg?.blockedSni?.length||0), caps?.limits?.sni)}<div className="toolbar"><input value={sni} onChange={e => setSNI(e.target.value)} placeholder="telemetry.example.com"/><button className="primary" onClick={() => call('/api/v1/ebpf/sni', 'POST', { name: sni })}>Add SNI</button></div><div className="chips">{(cfg?.blockedSni || []).map((x: string) => <button key={x} onClick={() => call('/api/v1/ebpf/sni/delete', 'POST', { name: x })}>{x} ×</button>)}</div></section>

    <section className="card"><p className="eyebrow">RATE CONTROL</p><h3>Destination PPS ceiling</h3><p>Simple fixed-window IPv4 destination packet-rate guard. Intended as an emergency containment control, not QoS.</p>{cap((cfg?.rateLimits?.length||0), caps?.limits?.rate)}<div className="ruleform"><input value={rateIP} onChange={e => setRateIP(e.target.value)} placeholder="203.0.113.20"/><input value={pps} onChange={e => setPPS(e.target.value)} inputMode="numeric"/><button className="primary" onClick={() => call('/api/v1/ebpf/rate', 'PUT', { destination: rateIP, pps: Number(pps) })}>Set PPS</button></div><div className="chips">{(cfg?.rateLimits || []).map((x: any) => <button key={x.destination} onClick={() => call('/api/v1/ebpf/rate/' + encodeURIComponent(x.destination), 'DELETE')}>{x.destination} · {x.pps}pps ×</button>)}</div></section>

    <section className="card span3"><p className="eyebrow">SHIELD</p><h3>DDoS per-source-class PPS shield</h3><p>Independent XDP-layer token-bucket limiter for SYN/UDP/ICMP/other floods, decoupled from the enforcement lease above. {shieldDiag?.summary && <>Live: {shieldDiag.summary.allowed||0} allowed · {shieldDiag.summary.dropped||0} dropped · {shieldDiag.summary.audited||0} audited.</>}</p><div className="ruleform"><select value={shieldMode} onChange={e => setShieldMode(e.target.value)}><option value="off">off</option><option value="audit">audit</option><option value="enforce">enforce</option></select><label><input type="checkbox" checked={shieldProtectAll} onChange={e => setShieldProtectAll(e.target.checked)}/> protect all</label><input value={shieldSyn} onChange={e => setShieldSyn(e.target.value)} inputMode="numeric" placeholder="SYN pps"/><input value={shieldUdp} onChange={e => setShieldUdp(e.target.value)} inputMode="numeric" placeholder="UDP pps"/><input value={shieldIcmp} onChange={e => setShieldIcmp(e.target.value)} inputMode="numeric" placeholder="ICMP pps"/><input value={shieldOther} onChange={e => setShieldOther(e.target.value)} inputMode="numeric" placeholder="other pps"/><input value={shieldBurst} onChange={e => setShieldBurst(e.target.value)} inputMode="numeric" placeholder="burst s"/><button className="primary" onClick={applyShield}>Apply shield config</button></div>{!shieldProtectAll && <div className="toolbar"><input value={shieldIP} onChange={e => setShieldIP(e.target.value)} placeholder="protected IPv4"/><button onClick={addShieldIP}>Add protected IP</button></div>}<div className="chips">{(cfg?.shield?.protectedIpv4 || []).map((x: string) => <button key={x} onClick={() => delShieldIP(x)}>{x} ×</button>)}</div></section>

    <section className="card span3"><p className="eyebrow">NETPOL</p><h3>Per-workload NetworkPolicy-style deny</h3><p>Legacy per-cgroup peer-deny engine, independent from the rules above. Rule authoring lands in a later phase — toggle enforcement and review existing entries here.</p><div className="toolbar"><button className={cfg?.netPolEnabled ? 'danger' : 'primary'} onClick={toggleNetPol}>{cfg?.netPolEnabled ? 'Disable NetPol' : 'Enable NetPol'}</button></div><div className="chips">{(cfg?.netPolDenies || []).length === 0 && <span>No NetPol deny entries.</span>}{(cfg?.netPolDenies || []).map((x: any, i: number) => <span key={i}>{x.direction || 'both'} · cgroup {x.cgroupId} → {x.peerIpv4}{x.port ? ':' + x.port : ''} {x.protocol || ''}</span>)}</div></section>

    <section className="card"><p className="eyebrow">CAPABILITIES</p><h3>Datapath capabilities</h3><p>{caps?.observability?.length || 0} observability classes and {caps?.enforcement?.length || 0} enforcement classes are exposed by this release.</p><div className="chips">{(caps?.hooks || []).map((x: string) => <span key={x}>{x}</span>)}</div></section>

    <div className="span3"><TerminalFrame title="standalone eBPF events"><div className="eventtools"><span>Recent flow, DNS, socket and block events</span><select value={eventType} onChange={e => setEventType(e.target.value)}><option value="all">all</option><option value="flow">flow</option><option value="dns">dns</option><option value="connect">connect</option><option value="block">block</option></select></div><div className="flowhead obs"><span>TIME / NODE</span><span>TYPE</span><span>PROCESS</span><span>FLOW / DNS</span><span>ACTION</span></div>{events.map((e: any, i) => <div className="flowrow obs" key={i}><span>{new Date(e.observedAt).toLocaleTimeString()} · {e.node}</span><span>{e.direction} {e.hook} · {e.type}</span><span>{e.namespace || e.pod ? `${e.namespace}/${e.pod} · ${e.comm || 'process?'} pid=${e.pid || 0}` : (e.comm ? `${e.comm} pid=${e.pid} uid=${e.uid}` : '—')}</span><span>{e.dnsQuery || `${e.sourceIp || '—'}:${e.sourcePort || 0} → ${e.destinationIp || '—'}:${e.destinationPort || 0} ${e.protocol}`}</span><span className={e.action === 'blocked' ? 'blocked' : ''}>{e.action}{e.reason ? ` · ${e.reason}` : ''}</span></div>)}</TerminalFrame></div>
    <div className="span3"><TerminalFrame title="exact flow counters"><div className="flowhead obs"><span>NODE / HOOK</span><span>DIR</span><span>FLOW</span><span>PROTO</span><span>PACKETS / BYTES / BLOCKED</span></div>{stats.map((s: any, i) => <div className="flowrow obs" key={i}><span>{s.node} · {s.hook}{s.namespace ? ` · ${s.namespace}/${s.pod}` : ''}</span><span>{s.direction}</span><span>{s.sourceIp || '—'}:{s.sourcePort || 0} → {s.destinationIp}:{s.port}</span><span>{s.protocol}</span><span>{s.packets} / {s.bytes} / {s.blocked}</span></div>)}</TerminalFrame></div>
    <div className="span3"><TerminalFrame title="workload network topology"><div className="flowhead obs"><span>WORKLOAD</span><span>NODE</span><span>DESTINATION</span><span>PROTO</span><span>PACKETS / BYTES / BLOCKED</span></div>{topology.map((e:any, i:number) => <div className="flowrow obs" key={i}><span>{e.namespace}/{e.pod}{e.workloadName ? ` · ${e.workloadKind}/${e.workloadName}` : ''}</span><span>{e.node}</span><span>{e.destination}</span><span>{e.protocol}</span><span>{e.packets} / {e.bytes} / {e.blocked}</span></div>)}</TerminalFrame></div>
    <section className="card span3"><p className="eyebrow">NODE COVERAGE</p><h3>Attached hooks</h3>{agents.map(a => <div className="agent wide" key={a.node}><b>{a.node}</b><span>{a.stale ? 'stale' : a.mode}</span><span>{(a.hooks || []).join(', ') || '—'}</span><small>{(a.workloads || []).length} workload cgroups · {a.scopeMode || 'all'} scope ({a.selectedCgroups || 0} selected) · {a.cgroupPath || 'no cgroup'} · interfaces: {(a.interfaces || []).join(', ') || 'cgroup-only'} · XDP: {(a.xdpInterfaces || []).join(', ') || 'off'}</small></div>)}</section>
  </div>;
}
