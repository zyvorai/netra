import { useEffect, useState } from 'react';
import { api } from '../api';

type Board = {
  id: string;
  label: string;
  group: string;
  path: string;
  note?: string;
  /** JSON path tips for common list keys */
  listKeys: string[];
};

const BOARDS: Board[] = [
  { id: 'tls', label: 'TLS fingerprints', group: 'Encrypted', path: '/api/v1/ebpf/tls-fingerprints?limit=100', listKeys: ['fingerprints'] },
  { id: 'tls-risk', label: 'JA3 risk', group: 'Encrypted', path: '/api/v1/ebpf/tls-fingerprints/risk?limit=100', listKeys: ['items'] },
  { id: 'encdns', label: 'Encrypted DNS', group: 'Encrypted', path: '/api/v1/ebpf/encrypted-dns?limit=100', listKeys: ['result.hits', 'result.items', 'hits'] },
  { id: 'ech', label: 'ECH / missing SNI', group: 'Encrypted', path: '/api/v1/insights/ech-blind?limit=100', listKeys: ['findings', 'items'] },
  { id: 'shadow', label: 'Shadow SaaS', group: 'Fit', path: '/api/v1/insights/shadow-saas?limit=100', listKeys: ['findings', 'items'] },
  { id: 'experience', label: 'Experience', group: 'Fit', path: '/api/v1/insights/experience?limit=100', listKeys: ['rows', 'items'] },
  { id: 'destrisk', label: 'Destination risk', group: 'Fit', path: '/api/v1/insights/destination-risk?limit=100', listKeys: ['items'] },
  { id: 'zt', label: 'Zero Trust drafts', group: 'Fit', path: '/api/v1/insights/zero-trust?limit=50', listKeys: ['drafts', 'items'] },
  { id: 'microseg', label: 'Microseg', group: 'Fit', path: '/api/v1/insights/microseg?limit=50', listKeys: ['suggestions', 'items', 'drafts'] },
  { id: 'packs', label: 'Policy packs', group: 'Fit', path: '/api/v1/insights/policy-packs?limit=50', listKeys: ['packs', 'items'] },
  { id: 'identity', label: 'Identity drafts', group: 'Fit', path: '/api/v1/insights/identity-drafts?limit=50', listKeys: ['drafts', 'items'] },
  { id: 'exfil', label: 'Exfil heuristics', group: 'Threat', path: '/api/v1/insights/exfil?limit=100', listKeys: ['findings', 'items'] },
  { id: 'lateral', label: 'Lateral playbooks', group: 'Threat', path: '/api/v1/insights/lateral?limit=50', listKeys: ['playbooks', 'items'] },
  { id: 'catdeny', label: 'Category deny', group: 'Threat', path: '/api/v1/insights/category-deny?limit=50', listKeys: ['drafts', 'items'] },
  { id: 'dnsintel', label: 'DNS intel hits', group: 'Threat', path: '/api/v1/intel/dns-hits?limit=100', listKeys: ['hits', 'items'] },
  { id: 'intel', label: 'Threat intel feed', group: 'Threat', path: '/api/v1/intel/feed', listKeys: ['entries', 'items'] },
  { id: 'appcat', label: 'App categories', group: 'Ops', path: '/api/v1/ebpf/app-categories?limit=100', listKeys: ['hits', 'items'] },
  { id: 'compliance', label: 'Compliance', group: 'Ops', path: '/api/v1/compliance?limit=100', listKeys: ['checks', 'items', 'findings'] },
  { id: 'ainet', label: 'AI destinations', group: 'Ops', path: '/api/v1/ebpf/ai-destinations?limit=100', listKeys: ['hits', 'items', 'destinations'] },
  { id: 'automitigate', label: 'Auto-mitigate', group: 'Ops', path: '/api/v1/ebpf/auto-mitigate', listKeys: ['recent', 'actions', 'items'] },
  { id: 'prevention', label: 'Prevention report', group: 'Ops', path: '/api/v1/report/prevention', listKeys: ['sections', 'items'] },
  { id: 'clusters', label: 'Fleet clusters', group: 'Fleet', path: '/api/v1/fleet/clusters', listKeys: ['clusters', 'items'] },
  { id: 'tenants', label: 'Fleet tenants', group: 'Fleet', path: '/api/v1/fleet/tenants', listKeys: ['tenants', 'items'] },
];

const GROUPS = ['Encrypted', 'Fit', 'Threat', 'Ops', 'Fleet'];

function dig(obj: any, path: string): any {
  return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

function pickList(data: any, keys: string[]): any[] {
  if (!data) return [];
  for (const k of keys) {
    const v = dig(data, k);
    if (Array.isArray(v)) return v;
  }
  if (Array.isArray(data)) return data;
  return [];
}

function rowLabel(row: any): string {
  return (
    row.ja3 ||
    row.sni ||
    row.host ||
    row.hostname ||
    row.name ||
    row.title ||
    row.id ||
    row.source ||
    row.destination ||
    row.category ||
    row.node ||
    row.tenant ||
    row.cluster ||
    row.check ||
    row.domain ||
    ''
  );
}

function rowMeta(row: any): string {
  const parts: string[] = [];
  if (row.severity) parts.push(String(row.severity));
  if (row.ja4) parts.push(`ja4 ${row.ja4}`);
  if (row.count != null) parts.push(`n=${row.count}`);
  if (row.score != null) parts.push(`score ${row.score}`);
  if (row.riskScore != null) parts.push(`risk ${row.riskScore}`);
  if (row.category) parts.push(String(row.category));
  if (row.mode) parts.push(String(row.mode));
  if (Array.isArray(row.reasons) && row.reasons.length) parts.push(row.reasons.join(', '));
  if (row.message) parts.push(String(row.message));
  if (row.note && !row.message) parts.push(String(row.note));
  if (row.rationale && Array.isArray(row.rationale)) parts.push(row.rationale.slice(0, 2).join('; '));
  return parts.filter(Boolean).join(' · ');
}

export default function Surfaces() {
  const [group, setGroup] = useState(GROUPS[0]);
  const [boardId, setBoardId] = useState(BOARDS[0].id);
  const [data, setData] = useState<any>();
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  const boards = BOARDS.filter((b) => b.group === group);
  const active = BOARDS.find((b) => b.id === boardId) || boards[0] || BOARDS[0];

  useEffect(() => {
    if (!boards.some((b) => b.id === boardId)) setBoardId(boards[0]?.id || BOARDS[0].id);
  }, [group]); // eslint-disable-line react-hooks/exhaustive-deps

  const load = () => {
    if (!active) return;
    setLoading(true);
    api<any>(active.path)
      .then((d) => {
        setData(d);
        setErr('');
      })
      .catch((e) => setErr(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 20000);
    return () => clearInterval(t);
  }, [active?.path]); // eslint-disable-line react-hooks/exhaustive-deps

  const list = pickList(data, active?.listKeys || []);
  const note = data?.note || active?.note || '';
  const statsBits: string[] = [];
  if (data?.stats) {
    if (data.stats.uniqueJa3 != null) statsBits.push(`${data.stats.uniqueJa3} unique JA3`);
    if (data.stats.enabled === false) statsBits.push('detector off');
  }
  if (data?.count != null) statsBits.push(`${data.count} items`);
  if (data?.uniqueJa3 != null) statsBits.push(`${data.uniqueJa3} unique JA3`);
  if (data?.echSightings != null) statsBits.push(`${data.echSightings} ECH`);
  if (data?.rare != null) statsBits.push(`${data.rare} rare`);

  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">OBSERVE-ONLY SURFACES</p>
        <h3>P1–P5 metadata boards</h3>
        <p>Encrypted traffic, fit maps, threat heuristics, and fleet rollups — review-only, no decrypt, no payload export.</p>
        <div className="chips" role="tablist" aria-label="Surface groups">
          {GROUPS.map((g) => (
            <button key={g} type="button" className={group === g ? 'primary' : ''} aria-pressed={group === g} onClick={() => setGroup(g)}>
              {g}
            </button>
          ))}
        </div>
        <div className="chips" role="tablist" aria-label="Boards" style={{ marginTop: '0.75rem' }}>
          {boards.map((b) => (
            <button key={b.id} type="button" className={active?.id === b.id ? 'primary' : ''} aria-pressed={active?.id === b.id} onClick={() => setBoardId(b.id)}>
              {b.label}
            </button>
          ))}
        </div>
      </section>

      <section className="card span3">
        <p className="eyebrow">{active?.group?.toUpperCase()}</p>
        <h3>
          {active?.label}
          {statsBits.length > 0 && <small> · {statsBits.join(' · ')}</small>}
        </h3>
        {note && <p>{note}</p>}
        {loading && <p className="empty-state">Loading…</p>}
        {err && <p className="warning">{err}</p>}
        {!loading && !err && list.length === 0 && <p className="empty-state">No rows yet — observe traffic or wait for agent sync.</p>}
        <div className="list">
          {list.slice(0, 200).map((row, i) => {
            const label = rowLabel(row) || `row ${i + 1}`;
            const meta = rowMeta(row);
            const sev = String(row.severity || '').toLowerCase();
            return (
              <div className={`agent wide${sev ? ` insightrow ${sev}` : ''}`} key={`${label}-${i}`}>
                <b className="truncate" title={label}>
                  {label}
                </b>
                {sev && <span className={`severity-badge ${sev === 'high' || sev === 'critical' ? 'warning' : 'info'}`}>{sev}</span>}
                {meta && <small>{meta}</small>}
              </div>
            );
          })}
        </div>
        {list.length > 0 && (
          <p>
            <small>
              Showing {Math.min(list.length, 200)} of {list.length} · <code>{active?.path.split('?')[0]}</code>
            </small>
          </p>
        )}
      </section>
    </div>
  );
}
