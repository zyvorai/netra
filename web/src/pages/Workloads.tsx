import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import LiveFlowTerminal from '../components/LiveFlowTerminal';
import PodExec from '../components/PodExec';
import PodLogs from '../components/PodLogs';
import VMVnc from '../components/VMVnc';
import { hasGlob, matchGlob } from '../lib/glob';

type Kind = 'pod' | 'vm';
type Detail = {
  kind: Kind;
  name: string;
  namespace: string;
  phase?: string;
  node?: string;
  podIP?: string;
  podName?: string;
  running?: boolean;
  labels?: Record<string, string>;
  containers?: { name: string; ready?: boolean }[];
  defaultContainer?: string;
  recommendedSelector: Record<string, string>;
  lockdownPolicy: string;
  lockedDown: boolean;
  policies: { name: string; namespace: string; lockdown: boolean }[];
};

const PAGE_SIZES = [50, 100, 200] as const;

export default function Workloads({ kind }: { kind: Kind }) {
  const [ns, setNs] = useState('');
  const [q, setQ] = useState('');
  const [items, setItems] = useState<any[]>([]);
  const [selected, setSelected] = useState<any>(null);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [msg, setMsg] = useState('');
  const [candidate, setCandidate] = useState('');
  const [receipt, setReceipt] = useState<any>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<(typeof PAGE_SIZES)[number]>(50);
  const [consoleEnabled, setConsoleEnabled] = useState(false);
  const title = kind === 'pod' ? 'Pods' : 'VMs';

  const nsTrim = ns.trim();
  const nsIsGlob = hasGlob(nsTrim);
  const apiNs = nsTrim && !nsIsGlob ? nsTrim : '';

  useEffect(() => {
    void api<{ consoleEnabled?: boolean }>('/api/v1/status')
      .then((s) => setConsoleEnabled(!!s.consoleEnabled))
      .catch(() => setConsoleEnabled(false));
  }, []);

  async function refresh() {
    try {
      const qs = apiNs ? `?namespace=${encodeURIComponent(apiNs)}` : '';
      const path = kind === 'pod' ? `/api/v1/pods${qs}` : `/api/v1/vms${qs}`;
      const x = await api<any>(path);
      setItems(x.items || []);
    } catch (e) {
      setMsg(String(e));
    }
  }

  useEffect(() => {
    void refresh();
  }, [apiNs, kind]);

  useEffect(() => {
    setPage(1);
  }, [ns, q, kind, pageSize]);

  async function open(x: any) {
    setSelected(x);
    try {
      setDetail(
        await api<Detail>(
          `/api/v1/workloads/${kind}/${encodeURIComponent(x.namespace)}/${encodeURIComponent(x.name)}`
        )
      );
    } catch (e) {
      setMsg(String(e));
    }
  }

  const filtered = useMemo(() => {
    return items.filter((x) => {
      if (nsIsGlob && !matchGlob(nsTrim, x.namespace || '')) return false;
      const needle = q.trim();
      if (!needle) return true;
      if (hasGlob(needle)) {
        return (
          matchGlob(needle, x.name || '') ||
          matchGlob(needle, x.node || '') ||
          matchGlob(needle, x.podIP || '')
        );
      }
      return (
        matchGlob(needle, x.name || '', { substring: true }) ||
        matchGlob(needle, x.node || '', { substring: true }) ||
        matchGlob(needle, x.podIP || '', { substring: true })
      );
    });
  }, [items, nsIsGlob, nsTrim, q]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * pageSize;
  const pageItems = filtered.slice(start, start + pageSize);
  const showingFrom = filtered.length === 0 ? 0 : start + 1;
  const showingTo = Math.min(start + pageSize, filtered.length);

  async function lockdown() {
    if (!detail) return;
    const x = await api<any>('/api/v1/policies/lockdown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        namespace: detail.namespace,
        name: detail.name,
        kind,
        selector: detail.recommendedSelector,
      }),
    });
    setCandidate(JSON.stringify(x));
    setReceipt(null);
    setMsg('Lockdown policy generated. Preflight before apply.');
  }

  async function preflight() {
    if (!candidate) return;
    const x = await api<any>('/api/v1/policies/plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: candidate,
    });
    setReceipt(x);
    setMsg(x.dryRun?.passed ? 'Preflight passed.' : 'Preflight failed.');
  }

  async function apply() {
    if (!candidate || !receipt?.receipt?.token) return;
    const risk = (receipt.plan?.risk || 'low').toLowerCase();
    if (['high', 'critical'].includes(risk) && !confirm(`Risk ${risk}. Apply?`)) return;
    const headers: any = {
      'Content-Type': 'application/json',
      'X-Netra-Plan-Token': receipt.receipt.token,
    };
    if (['high', 'critical'].includes(risk)) headers['X-Netra-Confirm-Risk'] = risk;
    await api('/api/v1/policies/apply?dryRun=false', { method: 'POST', headers, body: candidate });
    setMsg('Applied.');
    if (selected) await open(selected);
    await refresh();
  }

  async function unlock() {
    if (!detail || !confirm(`Unlock ${detail.namespace}/${detail.name}?`)) return;
    await api(
      `/api/v1/policies/lockdown/${encodeURIComponent(detail.namespace)}/${encodeURIComponent(detail.name)}`,
      { method: 'DELETE' }
    );
    setMsg('Unlocked.');
    if (selected) await open(selected);
    await refresh();
  }

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">FILTERS</p>
        <h3>{title} inventory</h3>
        <div className="toolbar">
          <input
            value={ns}
            placeholder="namespace (all, kube-*)"
            onChange={(e) => setNs(e.target.value)}
          />
          <input
            value={q}
            placeholder="search name / node / IP"
            onChange={(e) => setQ(e.target.value)}
          />
          <button onClick={refresh}>Refresh</button>
        </div>
        {msg && <p>{msg}</p>}
      </section>
      <section className="card span2">
        <h3>{title}</h3>
        <div className="toolbar">
          <label>
            Per page{' '}
            <select
              value={pageSize}
              onChange={(e) => setPageSize(Number(e.target.value) as (typeof PAGE_SIZES)[number])}
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <span>
            Showing {showingFrom}–{showingTo} of {filtered.length}
          </span>
          <button disabled={safePage <= 1} onClick={() => setPage(safePage - 1)}>
            Prev
          </button>
          <span>
            Page {safePage} / {totalPages}
          </span>
          <button disabled={safePage >= totalPages} onClick={() => setPage(safePage + 1)}>
            Next
          </button>
        </div>
        <div className="list">
          {pageItems.map((x) => (
            <button key={`${x.namespace}/${x.name}`} onClick={() => open(x)}>
              <span>
                <b>{x.name}</b>
                <small style={{ display: 'block' }}>
                  {x.namespace}
                  {x.node ? ` · ${x.node}` : ''}
                  {x.podIP ? ` · ${x.podIP}` : ''}
                </small>
              </span>
              <span>{x.lockedDown ? 'LOCKED' : x.phase || (x.running ? 'Running' : '—')}</span>
            </button>
          ))}
        </div>
      </section>
      <section className="card">
        <h3>Entity</h3>
        {detail ? (
          <>
            <p>
              <b>
                {detail.namespace}/{detail.name}
              </b>
            </p>
            <p>
              {detail.node}
              {detail.podIP ? ` · ${detail.podIP}` : ''}
            </p>
            <div className="toolbar">
              <button className="danger" onClick={lockdown} disabled={detail.lockedDown}>
                Lock down
              </button>
              <button onClick={unlock} disabled={!detail.lockedDown}>
                Unlock
              </button>
              <button onClick={preflight} disabled={!candidate}>
                Preflight
              </button>
              <button className="primary" onClick={apply} disabled={!receipt?.receipt?.token}>
                Apply
              </button>
            </div>
          </>
        ) : (
          <p>Select a {kind}.</p>
        )}
      </section>
      {detail && consoleEnabled && kind === 'pod' && (
        <>
          <PodLogs
            namespace={detail.namespace}
            name={detail.name}
            containers={detail.containers}
            defaultContainer={detail.defaultContainer}
          />
          <PodExec
            namespace={detail.namespace}
            name={detail.name}
            containers={detail.containers}
            defaultContainer={detail.defaultContainer}
          />
        </>
      )}
      {detail && consoleEnabled && kind === 'vm' && (
        <VMVnc namespace={detail.namespace} name={detail.name} />
      )}
      {detail && (
        <section className="card span3">
          <h3>
            Live flows for {detail.namespace}/{detail.name}
          </h3>
          <LiveFlowTerminal
            initial={{
              namespace: detail.namespace,
              pod: detail.podName || detail.name,
              direction: 'EGRESS',
            }}
            lockedScope
            showFilters
          />
        </section>
      )}
    </div>
  );
}
