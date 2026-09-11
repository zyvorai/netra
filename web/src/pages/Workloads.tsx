import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import LiveFlowTerminal from '../components/LiveFlowTerminal';

type Kind = 'pod' | 'vm';

type PlanResponse = {
  plan: {
    risk: string;
    changes: string[];
    warnings: string[];
    addedDestinations: string[];
    removedDestinations: string[];
  };
  dryRun: { passed: boolean; error?: string };
  receipt?: { token: string; expiresAt: string } | null;
};

type WorkloadDetail = {
  kind: Kind;
  name: string;
  namespace: string;
  phase?: string;
  node?: string;
  podIP?: string;
  podName?: string;
  ready?: boolean;
  running?: boolean;
  labels?: Record<string, string>;
  recommendedSelector: Record<string, string>;
  lockdownPolicy: string;
  lockedDown: boolean;
  policies: { name: string; namespace: string; lockdown: boolean }[];
};

type Props = { kind: Kind };

export default function Workloads({ kind }: Props) {
  const [ns, setNs] = useState('');
  const [q, setQ] = useState('');
  const [items, setItems] = useState<any[]>([]);
  const [available, setAvailable] = useState(true);
  const [msg, setMsg] = useState('');
  const [selected, setSelected] = useState<{ namespace: string; name: string } | null>(null);
  const [detail, setDetail] = useState<WorkloadDetail | null>(null);
  const [plan, setPlan] = useState<PlanResponse | null>(null);
  const [candidate, setCandidate] = useState('');
  const [builder, setBuilder] = useState({
    name: '',
    kind: 'fqdn',
    to: 'api.example.com',
    port: '443',
    protocol: 'TCP',
    includeDns: true,
  });

  const title = kind === 'pod' ? 'Pods' : 'VMs';

  async function refresh() {
    try {
      const path =
        kind === 'pod'
          ? `/api/v1/pods${ns ? `?namespace=${encodeURIComponent(ns)}` : ''}`
          : `/api/v1/vms${ns ? `?namespace=${encodeURIComponent(ns)}` : ''}`;
      const x = await api<any>(path);
      setItems(x.items || []);
      if (kind === 'vm') setAvailable(x.available !== false);
      setMsg('');
    } catch (e) {
      setMsg(String(e));
    }
  }

  useEffect(() => {
    void refresh();
  }, [ns, kind]);

  async function openEntity(namespace: string, name: string) {
    setSelected({ namespace, name });
    setPlan(null);
    setCandidate('');
    try {
      const d = await api<WorkloadDetail>(`/api/v1/workloads/${kind}/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`);
      setDetail(d);
      setBuilder((b) => ({
        ...b,
        name: `${kind}-${name}-egress`.slice(0, 63).replace(/[^a-z0-9-]/gi, '-').toLowerCase(),
      }));
    } catch (e) {
      setMsg(String(e));
      setDetail(null);
    }
  }

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((it) =>
      [it.name, it.namespace, it.node, it.podIP, it.podName].filter(Boolean).some((v: string) => String(v).toLowerCase().includes(needle)),
    );
  }, [items, q]);

  const flowScope = useMemo(() => {
    if (!detail) return undefined;
    return {
      namespace: detail.namespace,
      pod: detail.podName || detail.name,
      direction: 'EGRESS',
    };
  }, [detail]);

  async function buildRule() {
    if (!detail) return;
    try {
      const destinations = builder.to.split(',').map((x) => x.trim()).filter(Boolean);
      const body = {
        name: builder.name || `${kind}-${detail.name}-egress`,
        namespace: detail.namespace,
        selector: detail.recommendedSelector,
        kind: builder.kind,
        to: destinations,
        port: builder.port ? Number(builder.port) : 0,
        protocol: builder.protocol,
        includeDns: builder.includeDns,
      };
      const x = await api('/api/v1/policies/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      setCandidate(JSON.stringify(x, null, 2));
      setPlan(null);
      setMsg('Rule generated. Run Preflight, then Apply.');
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function lockdown() {
    if (!detail) return;
    try {
      const x = await api('/api/v1/policies/lockdown', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          namespace: detail.namespace,
          name: detail.name,
          kind,
          selector: detail.recommendedSelector,
        }),
      });
      setCandidate(typeof x === 'string' ? x : JSON.stringify(x, null, 2));
      // api() always parses JSON — lockdown returns raw CNP object
      setCandidate(JSON.stringify(x, null, 2));
      setPlan(null);
      setMsg('Lockdown CNP ready. Run Preflight, then Apply.');
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function preflight() {
    if (!candidate) return;
    try {
      const x = await api<PlanResponse>('/api/v1/policies/plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: candidate,
      });
      setPlan(x);
      setMsg(x.dryRun.passed ? 'Preflight passed. Apply within five minutes.' : 'Preflight dry-run failed.');
    } catch (e) {
      setPlan(null);
      setMsg(String(e));
    }
  }

  async function apply() {
    if (!plan?.dryRun?.passed || !plan.receipt?.token) {
      setMsg('Run Preflight before apply.');
      return;
    }
    const risk = plan.plan.risk.toLowerCase();
    if ((risk === 'high' || risk === 'critical') && !confirm(`Risk is ${risk.toUpperCase()}. Apply anyway?`)) return;
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Netra-Plan-Token': plan.receipt.token,
      };
      if (risk === 'high' || risk === 'critical') headers['X-Netra-Confirm-Risk'] = risk;
      await api('/api/v1/policies/apply?dryRun=false', { method: 'POST', headers, body: candidate });
      setMsg('Policy applied.');
      setPlan(null);
      if (selected) await openEntity(selected.namespace, selected.name);
      await refresh();
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function deleteRule(namespace: string, name: string) {
    if (!confirm(`Delete CiliumNetworkPolicy ${namespace}/${name}?`)) return;
    try {
      await api(`/api/v1/policies/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`, { method: 'DELETE' });
      setMsg(`Deleted ${namespace}/${name}`);
      if (selected) await openEntity(selected.namespace, selected.name);
      await refresh();
    } catch (e) {
      setMsg(String(e));
    }
  }

  async function unlock() {
    if (!detail) return;
    if (!confirm(`Unlock ${detail.namespace}/${detail.name}? This deletes ${detail.lockdownPolicy}.`)) return;
    try {
      await api(`/api/v1/policies/lockdown/${encodeURIComponent(detail.namespace)}/${encodeURIComponent(detail.name)}`, {
        method: 'DELETE',
      });
      setMsg('Unlocked.');
      if (selected) await openEntity(selected.namespace, selected.name);
      await refresh();
    } catch (e) {
      setMsg(String(e));
    }
  }

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">{kind === 'pod' ? 'WORKLOADS' : 'KUBEVIRT'}</p>
        <h2>{title}</h2>
        <p>Inventory, live per-entity flows, create/delete rules, and one-click quarantine.</p>
        <div className="toolbar">
          <input value={ns} placeholder="namespace (all)" onChange={(e) => setNs(e.target.value)} />
          <input value={q} placeholder="search" onChange={(e) => setQ(e.target.value)} />
          <button onClick={refresh}>Refresh</button>
        </div>
        {msg && <p>{msg}</p>}
        {kind === 'vm' && !available && <p className="warning">KubeVirt is not installed in this cluster. The VMs page stays empty until VirtualMachineInstances exist.</p>}
      </section>

      <section className="card span2">
        <h3>{title} inventory</h3>
        <div className="list">
          {filtered.length === 0 && <p>No {title.toLowerCase()} found.</p>}
          {filtered.map((it) => (
            <button
              key={`${it.namespace}/${it.name}`}
              className={selected?.name === it.name && selected?.namespace === it.namespace ? 'primary' : ''}
              onClick={() => openEntity(it.namespace, it.name)}
            >
              <span>
                <b>{it.name}</b>
                <small style={{ display: 'block', color: '#777' }}>
                  {it.namespace}
                  {it.node ? ` · ${it.node}` : ''}
                  {it.podIP ? ` · ${it.podIP}` : ''}
                </small>
              </span>
              <span>
                {it.lockedDown ? 'LOCKED' : it.phase || (it.running ? 'Running' : '—')}
              </span>
            </button>
          ))}
        </div>
      </section>

      <section className="card">
        <h3>Entity</h3>
        {!detail && <p>Select a {kind} to inspect flows and rules.</p>}
        {detail && (
          <>
            <p>
              <b>
                {detail.namespace}/{detail.name}
              </b>
            </p>
            <p>
              {detail.phase || (detail.running ? 'Running' : '')}
              {detail.node ? ` · ${detail.node}` : ''}
              {detail.podIP ? ` · ${detail.podIP}` : ''}
              {detail.podName && detail.podName !== detail.name ? ` · pod ${detail.podName}` : ''}
            </p>
            <p>
              Selector:{' '}
              {Object.entries(detail.recommendedSelector || {})
                .map(([k, v]) => `${k}=${v}`)
                .join(', ') || 'none'}
            </p>
            <div className="toolbar">
              <button className="danger" onClick={lockdown} disabled={detail.lockedDown}>
                Lock down
              </button>
              <button onClick={unlock} disabled={!detail.lockedDown}>
                Unlock
              </button>
            </div>
            {detail.lockedDown && <p className="warning">Quarantined via {detail.lockdownPolicy}</p>}
          </>
        )}
      </section>

      {detail && (
        <>
          <section className="card span3">
            <p className="eyebrow">RULES</p>
            <h3>Policies for this {kind}</h3>
            <div className="list">
              {(detail.policies || []).length === 0 && <p>No matching CiliumNetworkPolicies.</p>}
              {(detail.policies || []).map((p) => (
                <div className="policyrow" key={p.name}>
                  <button onClick={() => setMsg(`${p.namespace}/${p.name}${p.lockdown ? ' (lockdown)' : ''}`)}>
                    <b>{p.name}</b>
                    <span>{p.lockdown ? 'lockdown' : 'rule'}</span>
                  </button>
                  <button className="policydelete" onClick={() => deleteRule(p.namespace, p.name)}>
                    Delete
                  </button>
                </div>
              ))}
            </div>

            <h3 style={{ marginTop: 24 }}>Create egress rule</h3>
            <div className="buildergrid">
              <label>
                Name
                <input value={builder.name} onChange={(e) => setBuilder({ ...builder, name: e.target.value })} />
              </label>
              <label>
                Type
                <select value={builder.kind} onChange={(e) => setBuilder({ ...builder, kind: e.target.value })}>
                  <option value="fqdn">FQDN</option>
                  <option value="cidr">CIDR</option>
                  <option value="entity">Entity</option>
                </select>
              </label>
              <label>
                Destination(s)
                <input value={builder.to} onChange={(e) => setBuilder({ ...builder, to: e.target.value })} placeholder="comma separated" />
              </label>
              <label>
                Port
                <input value={builder.port} onChange={(e) => setBuilder({ ...builder, port: e.target.value })} />
              </label>
              <label>
                Protocol
                <select value={builder.protocol} onChange={(e) => setBuilder({ ...builder, protocol: e.target.value })}>
                  <option>TCP</option>
                  <option>UDP</option>
                </select>
              </label>
              <label className="check">
                <input type="checkbox" checked={builder.includeDns} onChange={(e) => setBuilder({ ...builder, includeDns: e.target.checked })} />
                Allow kube-dns
              </label>
            </div>
            <div className="toolbar" style={{ marginTop: 12 }}>
              <button className="primary" onClick={buildRule}>
                Generate rule
              </button>
              <button onClick={preflight} disabled={!candidate}>
                Preflight
              </button>
              <button className="primary" onClick={apply} disabled={!plan?.receipt?.token}>
                Apply
              </button>
            </div>
            {plan && (
              <div className={`risk risk-${plan.plan.risk.toLowerCase()}`}>
                <b>{plan.plan.risk.toUpperCase()}</b>
                <span>{plan.dryRun.passed ? 'dry-run passed' : 'dry-run failed'}</span>
              </div>
            )}
            {candidate && (
              <pre style={{ marginTop: 12, fontSize: 11, overflow: 'auto', maxHeight: 220, background: '#f5f5f7', padding: 12, borderRadius: 12 }}>
                {candidate}
              </pre>
            )}
          </section>

          <section className="card span3">
            <p className="eyebrow">LIVE FLOWS</p>
            <h2>
              Traffic for {detail.namespace}/{detail.name}
            </h2>
            <LiveFlowTerminal
              title={`flows · ${detail.namespace}/${detail.podName || detail.name}`}
              initial={flowScope}
              lockedScope
              showFilters
            />
          </section>
        </>
      )}
    </div>
  );
}
