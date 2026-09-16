import { describe, expect, it } from 'vitest';
import { STAGES, nodeStageSeverity, stageForLayer, stageSummaries, worstSeverity } from './CongestionMap';

// The 11 layers below are grepped directly from internal/kerneldiag/analyze.go's
// `Layer: "..."` literals. If a 12th is ever added there without a matching
// STAGES entry in CongestionMap.tsx, this test starts failing — that's the point.
const REAL_LAYERS = [
  'softnet-backlog',
  'softnet-budget',
  'tcp-receive',
  'socket-receive',
  'socket-send',
  'tcp-listen',
  'tcp-memory',
  'qdisc',
  'conntrack',
  'nic-driver',
  'ip',
];

describe('stageForLayer', () => {
  it('maps every real Layer literal to a stage', () => {
    for (const layer of REAL_LAYERS) {
      expect(stageForLayer(layer), `layer ${layer} should map to a stage`).toBeDefined();
    }
  });

  it('returns undefined for an unknown layer', () => {
    expect(stageForLayer('made-up-layer')).toBeUndefined();
  });

  it('covers every layer referenced by STAGES exactly once', () => {
    const allLayers = STAGES.flatMap((s) => s.layers);
    expect(new Set(allLayers).size).toBe(allLayers.length);
  });
});

describe('worstSeverity', () => {
  it('ranks critical above warning above ok above warming', () => {
    expect(worstSeverity(['ok', 'critical', 'warning'])).toBe('critical');
    expect(worstSeverity(['ok', 'warning'])).toBe('warning');
    expect(worstSeverity(['warming', 'ok'])).toBe('ok');
    expect(worstSeverity(['warming', 'warming'])).toBe('warming');
  });

  it('defaults to ok for an empty list', () => {
    expect(worstSeverity([])).toBe('ok');
  });
});

describe('nodeStageSeverity', () => {
  const stage = STAGES.find((s) => s.key === 'napi-softnet')!;

  it('returns the worst severity among matching findings', () => {
    const node = {
      node: 'n1',
      window: { warming: false },
      findings: [
        { severity: 'warning', layer: 'softnet-backlog', signal: 'a', explanation: '', recommendation: '', risk: '' },
        { severity: 'critical', layer: 'softnet-budget', signal: 'b', explanation: '', recommendation: '', risk: '' },
      ],
    };
    expect(nodeStageSeverity(node, stage)).toBe('critical');
  });

  it('returns warming when the node window is warming and has no matching findings', () => {
    const node = { node: 'n1', window: { warming: true }, findings: [] };
    expect(nodeStageSeverity(node, stage)).toBe('warming');
  });

  it('returns ok when not warming and no matching findings', () => {
    const node = { node: 'n1', window: { warming: false }, findings: [] };
    expect(nodeStageSeverity(node, stage)).toBe('ok');
  });

  it('ignores findings from unrelated layers', () => {
    const node = {
      node: 'n1',
      window: { warming: false },
      findings: [{ severity: 'critical', layer: 'qdisc', signal: 'x', explanation: '', recommendation: '', risk: '' }],
    };
    expect(nodeStageSeverity(node, stage)).toBe('ok');
  });
});

describe('stageSummaries', () => {
  it('aggregates worst-per-node severity across the whole cluster', () => {
    const nodes = [
      {
        node: 'n1',
        window: { warming: false },
        findings: [{ severity: 'critical', layer: 'qdisc', signal: 'x', explanation: '', recommendation: '', risk: '' }],
      },
      { node: 'n2', window: { warming: false }, findings: [] },
    ];
    const out = stageSummaries(nodes);
    expect(out.get('qdisc')?.severity).toBe('critical');
    expect(out.get('qdisc')?.perNode.map((p) => p.severity)).toEqual(['critical', 'ok']);
    expect(out.get('nic-driver')?.severity).toBe('ok');
  });

  it('shows warming, never a false-clean ok, when every node is still warming', () => {
    const nodes = [
      { node: 'n1', window: { warming: true }, findings: [] },
      { node: 'n2', window: { warming: true }, findings: [] },
    ];
    const out = stageSummaries(nodes);
    for (const stage of STAGES) {
      expect(out.get(stage.key)?.severity).toBe('warming');
    }
  });

  it('has one summary entry per declared stage', () => {
    const out = stageSummaries([]);
    expect(out.size).toBe(STAGES.length);
  });
});
