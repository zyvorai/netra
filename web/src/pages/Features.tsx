import { useEffect, useState } from 'react';
import { api } from '../api';

type FeatureStatus = {
  id: string;
  title: string;
  description: string;
  scope: string;
  helmSet: string;
  cli: string;
  enabled: boolean;
  source: string;
  note?: string;
};

type FeaturesResponse = {
  features: FeatureStatus[];
  summary?: { on: number; off: number; unknown: number };
  note?: string;
};

export default function Features() {
  const [data, setData] = useState<FeaturesResponse>();
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState('');

  async function refresh() {
    try {
      const r = await api<FeaturesResponse>('/api/v1/features');
      setData(r);
      setErr('');
    } catch (e) {
      setErr(String(e));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function toggle(f: FeatureStatus, enabled: boolean) {
    const action = enabled ? 'enable' : 'disable';
    if (!confirm(`${action} “${f.title}”?\n\nThis patches live Deployment/DaemonSet env (risk: high).\nPrefer durable: ${f.cli.replace('enable', action)} --yes`)) {
      return;
    }
    setBusy(f.id);
    setMsg('');
    try {
      await api(`/api/v1/features/${encodeURIComponent(f.id)}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Netra-Confirm-Risk': 'high',
        },
        body: JSON.stringify({ enabled }),
      });
      setMsg(`${f.id} → ${enabled ? 'on' : 'off'} (pod may restart). Helm remains source of truth.`);
      await refresh();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy('');
    }
  }

  const rows = data?.features || [];

  return (
    <div className="grid">
      <section className="card span2">
        <p className="eyebrow">CAPABILITY FLAGS</p>
        <h3>Install-time features</h3>
        <p>
          Toggle observe-only detectors, optional integrations, and agent coverage. This does not flip enforce mode or
          apply deny rules. Durable desired state: <code>netractl features enable NAME --yes</code> (Helm).
        </p>
        {data?.summary && (
          <div className="metrics">
            <div>
              <b>{data.summary.on}</b>
              <span>on</span>
            </div>
            <div>
              <b>{data.summary.off}</b>
              <span>off</span>
            </div>
            <div>
              <b>{data.summary.unknown}</b>
              <span>unknown</span>
            </div>
          </div>
        )}
        {err && <p className="warning">{err}</p>}
        {msg && <p className="warning">{msg}</p>}
      </section>

      <section className="card span2">
        <table className="table">
          <thead>
            <tr>
              <th>Feature</th>
              <th>Scope</th>
              <th>State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const state = f.source === 'unknown' ? '?' : f.enabled ? 'on' : 'off';
              const agentOnly = f.id === 'agent';
              return (
                <tr key={f.id}>
                  <td>
                    <strong>{f.title}</strong>
                    <div className="muted">{f.description}</div>
                    <code className="muted">{f.cli}</code>
                    {f.note && <div className="muted">{f.note}</div>}
                  </td>
                  <td>{f.scope}</td>
                  <td>{state}</td>
                  <td>
                    {!agentOnly && (
                      <>
                        <button
                          className="primary"
                          disabled={busy === f.id || f.enabled}
                          onClick={() => void toggle(f, true)}
                        >
                          Enable
                        </button>{' '}
                        <button disabled={busy === f.id || (!f.enabled && f.source !== 'unknown')} onClick={() => void toggle(f, false)}>
                          Disable
                        </button>
                      </>
                    )}
                    {agentOnly && <span className="muted">CLI / Helm only</span>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </div>
  );
}
