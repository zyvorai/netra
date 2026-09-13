import { useState } from 'react';
import { api } from '../api';

type Brief = {
  headline: string;
  severity: string;
  summary: string;
  findings?: { severity?: string; message: string }[];
  nextSteps?: string[];
  fingerprint?: string;
  engine?: string;
};

export default function ExplainFinding(props: {
  page: string;
  kind: string;
  subject?: string;
  message?: string;
  severity?: string;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [brief, setBrief] = useState<Brief | null>(null);

  async function run() {
    if (busy) return;
    setOpen(true);
    setBusy(true);
    setErr('');
    try {
      const b = await api<Brief>('/api/v1/ai/explain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          page: props.page,
          kind: props.kind,
          subject: props.subject || '',
          message: props.message || '',
          severity: props.severity || '',
        }),
      });
      setBrief(b);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="explain-finding">
      <button type="button" className="ask-chip" onClick={() => void run()} disabled={busy} aria-label={`Explain ${props.kind}`}>
        {busy ? 'Explaining…' : 'Explain'}
      </button>
      {open && (
        <div className="explain-pop">
          {err && <p className="warning">{err}</p>}
          {brief && (
            <>
              <p>
                <span className={`severity-badge ${brief.severity || 'info'}`}>{brief.severity || 'info'}</span>{' '}
                <b>{brief.headline}</b>
              </p>
              <p>{brief.summary}</p>
              {(brief.nextSteps || []).slice(0, 3).map((s) => (
                <p key={s} className="ask-netra-meta">{s}</p>
              ))}
            </>
          )}
          <button type="button" className="btn-secondary" onClick={() => setOpen(false)}>Close</button>
        </div>
      )}
    </span>
  );
}
