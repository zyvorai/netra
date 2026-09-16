import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import ExplainFinding from '../components/ExplainFinding';

type KernelFinding = {
  severity: string;
  layer: string;
  signal: string;
  evidence?: string[];
  explanation: string;
  recommendation: string;
  risk: string;
  tunable?: string;
  currentValue?: string;
  suggestedValue?: string;
  applyCommand?: string;
  rollbackCommand?: string;
};
type KernelWindow = { warming: boolean; resetDetected?: boolean; resetSignals?: string[]; seconds?: number };
type KernelNode = { node: string; window?: KernelWindow; findings?: KernelFinding[] };
type KernelResponse = { summary?: { nodes?: number; findings?: number; critical?: number; warnings?: number; warming?: number }; nodes?: KernelNode[] };

export type StageKey = 'nic-driver' | 'napi-softnet' | 'ip' | 'tcp-listen' | 'socket-receive' | 'socket-send' | 'qdisc' | 'conntrack' | 'tcp-memory';
export type StageColumn = 'ingress' | 'shared' | 'egress';
export type StageSeverity = 'critical' | 'warning' | 'ok' | 'warming';
export type Stage = { key: StageKey; title: string; column: StageColumn; row: number; layers: string[]; caption?: string };

// The `layers` lists below are the 11 raw Layer string literals emitted by
// internal/kerneldiag/analyze.go's `add(models.KernelNetworkFinding{Layer:
// "..."})` call sites — grepped directly, not guessed. If that file ever
// adds a 12th Layer literal, stageForLayer's test (parametrized over all 11)
// will start failing a coverage assumption and this table needs a new row.
//
// Ingress and egress are genuinely different paths through the kernel, so
// this is laid out as three columns (ingress / shared / egress) across 7
// rows, per docs/kernel-network-diagnostics.md's "Where congestion and
// drops occur" table — not a single misleadingly linear pipe.
export const STAGES: Stage[] = [
  { key: 'nic-driver', title: 'NIC / driver ring', column: 'shared', row: 1, layers: ['nic-driver'] },
  { key: 'napi-softnet', title: 'NAPI / softirq backlog', column: 'ingress', row: 2, layers: ['softnet-backlog', 'softnet-budget'] },
  { key: 'ip', title: 'IP layer', column: 'shared', row: 3, layers: ['ip'] },
  { key: 'conntrack', title: 'Conntrack', column: 'shared', row: 3, layers: ['conntrack'] },
  { key: 'tcp-listen', title: 'TCP accept / SYN queue', column: 'ingress', row: 4, layers: ['tcp-listen'] },
  { key: 'socket-receive', title: 'Socket receive, TCP + UDP', column: 'ingress', row: 5, layers: ['tcp-receive', 'socket-receive'] },
  { key: 'socket-send', title: 'Socket send, UDP', column: 'egress', row: 5, layers: ['socket-send'] },
  { key: 'qdisc', title: 'Egress qdisc', column: 'egress', row: 6, layers: ['qdisc'], caption: 'Egress packets return through the same NIC/driver ring shown above.' },
  { key: 'tcp-memory', title: 'TCP memory pressure', column: 'shared', row: 7, layers: ['tcp-memory'] },
];

// Deliberately blank cells, rendered as muted dashed placeholders rather
// than silently omitted — this is what keeps the diagram honest about
// where the ingress/egress metaphor doesn't apply, instead of just
// prettifying a linear pipe that doesn't reflect the real packet path.
export const BLANK_CELLS: { column: StageColumn; row: number; caption: string }[] = [
  { column: 'egress', row: 2, caption: 'No egress NAPI/softirq backlog — that queue is RX-only.' },
  { column: 'egress', row: 4, caption: 'No egress SYN/accept queue — connection setup is inbound-only.' },
  { column: 'ingress', row: 6, caption: 'Ingress ends at the socket above — there is no separate ingress qdisc stage.' },
];

const SEVERITY_RANK: Record<StageSeverity, number> = { warming: 0, ok: 1, warning: 2, critical: 3 };

const layerToStage = new Map<string, StageKey>();
for (const s of STAGES) for (const l of s.layers) layerToStage.set(l, s.key);

export function stageForLayer(layer: string): StageKey | undefined {
  return layerToStage.get(layer);
}

// Empty input defaults to 'ok': stageSummaries only ever calls this with at
// least the per-node severities for every reporting node, so an empty list
// here means "no nodes reporting at all" — a fleet-visibility problem the
// rest of the dashboard (stale-agent counts) already covers, not something
// this diagram should render as 'warming' or invent a fifth state for.
export function worstSeverity(list: StageSeverity[]): StageSeverity {
  let worst: StageSeverity = 'ok';
  let worstRank = -1;
  for (const s of list) {
    if (SEVERITY_RANK[s] > worstRank) {
      worst = s;
      worstRank = SEVERITY_RANK[s];
    }
  }
  return worst;
}

// A warming node reports zero findings by construction (the controller
// zeroes counters while a node's rate window warms up) — that is NOT the
// same as "measured and healthy". Collapsing it into 'ok' would show a
// falsely clean grid right after every fleet-wide agent restart, including
// the one a fresh deploy causes. 'warming' ranks lowest in worstSeverity,
// so one real 'ok' node still wins over a warming one, but a stage where
// every contributing node is warming correctly shows 'warming', never a
// false-clean 'ok'.
export function nodeStageSeverity(node: KernelNode, stage: Stage): StageSeverity {
  const relevant = (node.findings || []).filter((f) => stage.layers.includes(f.layer));
  let worst: StageSeverity | null = null;
  for (const f of relevant) {
    const sev: StageSeverity = f.severity === 'critical' ? 'critical' : 'warning';
    if (!worst || SEVERITY_RANK[sev] > SEVERITY_RANK[worst]) worst = sev;
  }
  if (worst) return worst;
  if (!node.window || node.window.warming) return 'warming';
  return 'ok';
}

export type StageSummary = { severity: StageSeverity; perNode: { node: string; severity: StageSeverity; findings: KernelFinding[] }[] };

export function stageSummaries(nodes: KernelNode[]): Map<StageKey, StageSummary> {
  const out = new Map<StageKey, StageSummary>();
  for (const stage of STAGES) {
    const perNode = nodes.map((n) => ({
      node: n.node,
      severity: nodeStageSeverity(n, stage),
      findings: (n.findings || []).filter((f) => stage.layers.includes(f.layer)),
    }));
    out.set(stage.key, { severity: worstSeverity(perNode.map((p) => p.severity)), perNode });
  }
  return out;
}

function colIndex(c: StageColumn): number {
  return c === 'ingress' ? 1 : c === 'egress' ? 3 : 2;
}

export default function CongestionMap() {
  const [kernel, setKernel] = useState<KernelResponse>();
  const [kernelWindow, setKernelWindow] = useState('5m');
  const [err, setErr] = useState('');
  const [selected, setSelected] = useState<StageKey | null>(null);

  const load = () =>
    api<KernelResponse>(`/api/v1/ebpf/kernel-network?window=${encodeURIComponent(kernelWindow)}`)
      .then((k) => {
        setKernel(k);
        setErr('');
      })
      .catch((e) => setErr(String(e)));

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kernelWindow]);

  const nodes = useMemo(() => kernel?.nodes || [], [kernel]);
  const summaries = useMemo(() => stageSummaries(nodes), [nodes]);
  const selectedStage = selected ? STAGES.find((s) => s.key === selected) : undefined;
  const selectedSummary = selected ? summaries.get(selected) : undefined;

  return (
    <div className="grid">
      {err && (
        <section className="card span3">
          <p className="warning">{err}</p>
        </section>
      )}
      <section className="card span3">
        <p className="eyebrow">CONGESTION MAP</p>
        <h3>Where the stack is under pressure</h3>
        <p>
          Every layer of the Linux network stack a packet can pass through, colored by the worst finding across the
          cluster right now. Ingress (receive) and egress (send) are genuinely different paths through the kernel —
          this diagram doesn't pretend otherwise. Click a stage for the per-node detail behind it.
        </p>
        <label>
          Diagnostic window
          <select value={kernelWindow} onChange={(e) => setKernelWindow(e.target.value)}>
            <option value="1m">1 minute</option>
            <option value="5m">5 minutes</option>
            <option value="15m">15 minutes</option>
            <option value="1h">1 hour</option>
          </select>
        </label>
        {!nodes.length && !err && <p className="empty-state">No kernel-network reports yet.</p>}
        {Boolean(nodes.length) && (
          <div className="congestion-grid">
            <span className="congestion-col-label" style={{ gridColumn: 1 }}>
              INGRESS
            </span>
            <span className="congestion-col-label" style={{ gridColumn: 3 }}>
              EGRESS
            </span>
            {STAGES.map((stage) => {
              const summary = summaries.get(stage.key);
              const sev = summary?.severity || 'ok';
              return (
                <button
                  key={stage.key}
                  type="button"
                  className={`stage-cell ${sev}${selected === stage.key ? ' selected' : ''}`}
                  style={{ gridColumn: colIndex(stage.column), gridRow: stage.row + 1 }}
                  onClick={() => setSelected(selected === stage.key ? null : stage.key)}
                >
                  <span className="stage-cell-title">{stage.title}</span>
                  {sev === 'warming' ? (
                    <span className="stage-cell-warming">warming</span>
                  ) : (
                    <span className={`severity-badge ${sev === 'ok' ? 'info' : sev}`}>{sev}</span>
                  )}
                  {stage.caption && <small>{stage.caption}</small>}
                </button>
              );
            })}
            {BLANK_CELLS.map((b) => (
              <div
                key={`${b.column}-${b.row}`}
                className="stage-cell blank"
                style={{ gridColumn: colIndex(b.column), gridRow: b.row + 1 }}
              >
                <small>{b.caption}</small>
              </div>
            ))}
          </div>
        )}
      </section>

      {selectedStage && selectedSummary && (
        <section className="card span3">
          <p className="eyebrow">STAGE DETAIL</p>
          <h3>{selectedStage.title}</h3>
          <div className="list">
            {selectedSummary.perNode.every((p) => p.findings.length === 0) && (
              <p className="empty-state">No current findings at this stage on any node.</p>
            )}
            {selectedSummary.perNode.map((p) =>
              p.findings.map((f, i) => (
                <div className="agent wide" key={`${p.node}-${f.signal}-${i}`}>
                  <b>{f.signal}</b>
                  <span className={`severity-badge ${f.severity}`}>{f.severity}</span>
                  <span>{p.node}</span>
                  <small>{(f.evidence || []).join(' · ')}</small>
                  <small>{f.explanation}</small>
                  <small>{f.recommendation}</small>
                  {f.tunable && (
                    <small>
                      {f.tunable}: {f.currentValue || 'unavailable'}
                      {f.suggestedValue ? ` → canary ${f.suggestedValue}` : ''}
                    </small>
                  )}
                  {f.applyCommand && <code>{f.applyCommand}</code>}
                  {f.rollbackCommand && <code>rollback: {f.rollbackCommand}</code>}
                  <small className="warning">Risk: {f.risk}</small>
                  <ExplainFinding
                    page="congestion"
                    kind={f.signal}
                    subject={`${p.node}/${f.layer}`}
                    message={`${f.explanation} ${f.recommendation}`}
                    severity={f.severity}
                  />
                </div>
              )),
            )}
          </div>
        </section>
      )}
    </div>
  );
}
