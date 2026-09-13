import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';

type Finding = { severity?: string; kind?: string; subject?: string; message: string };
type Brief = {
  headline: string;
  severity: string;
  summary: string;
  findings: Finding[];
  nextSteps: string[];
  engine: string;
  model?: string;
  question?: string;
  fingerprint?: string;
  generatedAt: string;
};
type AIStatus = {
  enabled: boolean;
  provider?: string;
  model?: string;
  heuristicOnly: boolean;
  mutations: string;
};

export const ASK_SUGGESTIONS = [
  'What looks unhealthy?',
  'Why are packets being dropped?',
  'Any new external exposure?',
  'Are we in enforce mode?',
  'What policy drafts need review?',
];

export function canAsk(question: string, busy: boolean): boolean {
  return !busy && question.trim().length > 0;
}

export function looksLikeDraft(question: string): boolean {
  return /\b(deny|block|drop|rate[- ]?limit|throttle|ban)\b/i.test(question);
}

type RuleDraft = {
  understood: boolean;
  confidence?: string;
  kind?: string;
  summary: string;
  cli?: string;
  warnings?: string[];
  note?: string;
  body?: Record<string, unknown>;
};
type Digest = { fingerprint: string; changed: boolean; card: string; suggestions?: string[] };

export default function AskNetra() {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [question, setQuestion] = useState('');
  const [brief, setBrief] = useState<Brief | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [chips, setChips] = useState<string[]>(ASK_SUGGESTIONS);
  const [draft, setDraft] = useState<RuleDraft | null>(null);
  const [digest, setDigest] = useState<Digest | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    api<AIStatus>('/api/v1/ai/status')
      .then((s) => {
        setStatus(s);
        setErr('');
      })
      .catch((e) => setErr(String(e)));
    api<Brief>('/api/v1/ai/brief')
      .then((b) => {
        setBrief(b);
        setErr('');
      })
      .catch((e) => setErr(String(e)));
    api<{ items?: string[] }>('/api/v1/ai/suggestions')
      .then((s) => {
        if (s.items && s.items.length) setChips(s.items);
      })
      .catch(() => undefined);
    api<Digest>('/api/v1/ai/digest')
      .then(setDigest)
      .catch(() => undefined);
  }, []);

  async function ask(q: string) {
    const text = q.trim();
    if (!text || busy) return;
    setBusy(true);
    setErr('');
    try {
      const b = await api<Brief>('/api/v1/ai/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: text }),
      });
      setBrief(b);
      setQuestion(text);
      if (looksLikeDraft(text)) {
        try {
          setDraft(await api<RuleDraft>('/api/v1/ai/draft', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: text }),
          }));
        } catch {
          setDraft(null);
        }
      } else {
        setDraft(null);
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    void ask(question);
  }

  const engineLabel = brief?.engine === 'llm'
    ? `LLM${brief.model ? ` · ${brief.model}` : ''}`
    : 'Heuristic brief';

  return (
    <section className="card span3 ask-netra">
      <p className="eyebrow">ASK NETRA</p>
      <h3>Read-only brief from live aggregates.</h3>
      <p>
        Answers come from agent, health, and insights counters Netra already computed.
        Nothing here flips enforce mode or applies policy.
      </p>
      <form className="toolbar ask-netra-form" onSubmit={onSubmit}>
        <label className="ask-netra-field">
          Question
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Why is DNS failing in kube-system?"
            aria-label="Ask Netra question"
            maxLength={500}
            disabled={busy}
          />
        </label>
        <button type="submit" className="primary" disabled={!canAsk(question, busy)}>
          {busy ? 'Asking…' : 'Ask'}
        </button>
        <button
          type="button"
          className="btn-secondary"
          disabled={busy}
          onClick={() => void ask('What looks unhealthy?')}
        >
          Refresh brief
        </button>
      </form>
      <div className="ask-netra-chips">
        {chips.map((s) => (
          <button
            key={s}
            type="button"
            className="ask-chip"
            disabled={busy}
            onClick={() => void ask(s)}
          >
            {s}
          </button>
        ))}
      </div>
      {status && (
        <p className="ask-netra-meta">
          {status.heuristicOnly ? 'Heuristic engine only.' : `Optional rewrite on · ${status.model || status.provider}`}
          {' · '}
          {status.mutations}
        </p>
      )}
      {err && <p className="warning">{err}</p>}
      {brief && (
        <div className="ask-netra-answer">
          <p>
            <span className={`severity-badge ${brief.severity || 'info'}`}>{brief.severity || 'info'}</span>
            {' '}
            <b>{brief.headline}</b>
            <span className="ask-netra-engine">{engineLabel}{brief.fingerprint ? ` · ${brief.fingerprint}` : ''}</span>
          </p>
          <p>{brief.summary}</p>
          {(brief.findings || []).length > 0 && (
            <ul className="ask-netra-list">
              {brief.findings.slice(0, 6).map((f, i) => (
                <li key={(f.kind || '') + (f.subject || '') + i}>
                  {f.severity && <span className={`severity-badge ${f.severity}`}>{f.severity}</span>}
                  {' '}
                  {f.message}
                </li>
              ))}
            </ul>
          )}
          {(brief.nextSteps || []).length > 0 && (
            <>
              <p className="eyebrow">NEXT</p>
              <ul className="ask-netra-list">
                {brief.nextSteps.slice(0, 5).map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
      {draft && (
        <div className="ask-netra-draft">
          <p className="eyebrow">RULE PREVIEW</p>
          <p>
            <b>{draft.understood ? draft.summary : 'Not a safe exact match'}</b>
            {draft.confidence && <span className="ask-netra-engine">{draft.confidence}</span>}
          </p>
          {draft.cli && <p><code>{draft.cli}</code></p>}
          <p className="ask-netra-meta">{draft.note}</p>
          {(draft.warnings || []).map((w) => (
            <p key={w} className="ask-netra-meta">{w}</p>
          ))}
        </div>
      )}
      {digest && (
        <div className="toolbar" style={{ marginTop: 12 }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              void navigator.clipboard?.writeText(digest.card);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? 'Copied digest' : 'Copy on-call card'}
          </button>
          {digest.fingerprint && (
            <span className="ask-netra-meta">
              Fingerprint {digest.fingerprint}{digest.changed ? ' · changed since last look' : ''}
            </span>
          )}
        </div>
      )}
      {!brief && !err && <p className="empty-state">Loading cluster brief…</p>}
    </section>
  );
}
