import { useEffect, useState } from 'react';
import { api, authHeaders } from '../api';

type HistoryEntry = {
  node: string;
  backend?: string;
  protocol?: string;
  host?: string;
  port?: number;
  requestor?: string;
  startedAt?: string;
  endedAt?: string;
  reason?: string;
  artifactId?: string;
  artifactBytes?: number;
  artifactFrames?: number;
  triggerSource?: string;
  triggerKind?: string;
};

const PAGE_SIZE = 20;

function fmtDuration(startedAt?: string, endedAt?: string): string {
  if (!startedAt || !endedAt) return '—';
  const ms = new Date(endedAt).getTime() - new Date(startedAt).getTime();
  if (!(ms > 0)) return '—';
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${s % 60}s`;
}

function isAuto(e: HistoryEntry): boolean {
  return !!e.artifactId || !!(e.requestor && e.requestor.startsWith('auto-capture'));
}

async function downloadArtifact(id: string) {
  const res = await fetch(`/api/v1/capture/artifacts/${encodeURIComponent(id)}`, {
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${id}.pcap`;
  a.click();
  URL.revokeObjectURL(url);
}

// CaptureHistory lists already-ended capture sessions. Manual captures are
// metadata-only; auto-capture rows may include a downloadable PCAP artifact.
export default function CaptureHistory({ onRepeat }: { onRepeat: (e: HistoryEntry) => void }) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [page, setPage] = useState(0);

  const load = () => api<{ entries?: HistoryEntry[] }>('/api/v1/capture/history?limit=100').then((x) => setEntries(x.entries || [])).catch(() => {});
  useEffect(() => { load(); }, []);
  useEffect(() => { setPage(0); }, [entries.length]);

  return (
    <section className="card span3">
      <p className="eyebrow">CAPTURE HISTORY</p>
      <h3>{entries.length} past session{entries.length === 1 ? '' : 's'}</h3>
      <div className="toolbar">
        <button className="btn-secondary" onClick={load}>Refresh</button>
        {entries.length > PAGE_SIZE && (
          <>
            <button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <span>Page {page + 1} of {Math.max(1, Math.ceil(entries.length / PAGE_SIZE))}</span>
            <button disabled={(page + 1) * PAGE_SIZE >= entries.length} onClick={() => setPage((p) => p + 1)}>Next</button>
          </>
        )}
      </div>
      {entries.length === 0 && <p className="empty-state">No past capture sessions yet.</p>}
      {entries.length > 0 && (
        <div className="datatable-scroll">
          <div className="datahead capture">
            <span>NODE</span>
            <span>TARGET</span>
            <span>BACKEND</span>
            <span>STARTED → ENDED</span>
            <span>ENDED BY</span>
          </div>
          {entries.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((e, i) => (
            <div className="datarow capture" key={i}>
              <span>
                {e.node}
                {isAuto(e) && <small> · Auto{e.triggerKind ? ` (${e.triggerSource}/${e.triggerKind})` : ''}</small>}
              </span>
              <span>{e.protocol || 'any'}{e.host ? ` · ${e.host}` : ''}{e.port ? `:${e.port}` : ''}</span>
              <span>{e.backend === 'afpacket' ? 'AF_PACKET' : 'eBPF'}</span>
              <span>{e.startedAt ? new Date(e.startedAt).toLocaleString() : '—'} → {e.endedAt ? new Date(e.endedAt).toLocaleTimeString() : '—'}<br /><small>{fmtDuration(e.startedAt, e.endedAt)}</small></span>
              <span>
                {e.requestor || 'unknown'} · {e.reason || '—'}
                <br />
                <button className="btn-secondary" onClick={() => onRepeat(e)}>Repeat</button>
                {e.artifactId && (
                  <>
                    {' '}
                    <button
                      className="btn-secondary"
                      onClick={() => downloadArtifact(e.artifactId!).catch(() => {})}
                    >
                      Download{e.artifactFrames ? ` (${e.artifactFrames} pkt)` : ''}
                    </button>
                  </>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
