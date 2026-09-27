import type { ReactNode } from 'react';
import AskNetra from '../components/AskNetra';
import DatapathHero from '../components/DatapathHero';
import Reveal from '../components/Reveal';
import Sparkline from '../components/Sparkline';
import type { Page } from '../components/Nav';
import { useCountUp } from '../hooks/useCountUp';
import { PULSE_INTERVAL_MS, useOverviewPulse } from '../hooks/useOverviewPulse';

type Navigate = (page: Page) => void;
type Tone = 'ok' | 'warn' | 'idle';

function Metric({ value, label }: { value: number | string; label: string }) {
  const numeric = typeof value === 'number' && Number.isFinite(value);
  const animated = useCountUp(numeric ? (value as number) : 0);
  return (
    <div>
      <b>{numeric ? Math.round(animated).toLocaleString() : value}</b>
      <span>{label}</span>
    </div>
  );
}

export function compact(n: number): string {
  if (!Number.isFinite(n)) return '—';
  const abs = Math.abs(n);
  if (abs >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (abs >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (abs >= 1e4) return (n / 1e3).toFixed(1) + 'K';
  if (abs >= 100) return Math.round(n).toLocaleString();
  return n.toFixed(abs < 10 && n !== 0 ? 1 : 0);
}

export function bytesRate(n: number): string {
  if (!Number.isFinite(n)) return '—';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${units[i]}`;
}

function PulseFigure({ label, value, format, series, tone }: { label: string; value?: number; format: (n: number) => string; series: number[]; tone?: Tone }) {
  const animated = useCountUp(value ?? 0);
  return (
    <div className={`overview-pulse__cell${tone ? ' tone-' + tone : ''}`}>
      <span>{label}</span>
      <b>{value === undefined ? '—' : format(animated)}</b>
      <div className="overview-pulse__spark">
        {series.length > 1 ? <Sparkline values={series} width={200} height={36} fill /> : <i>warming up…</i>}
      </div>
    </div>
  );
}

function StatusPill({ agents, stale, leaseUntil }: { agents: number; stale: number; leaseUntil?: string }) {
  if (leaseUntil) {
    return (
      <span className="overview-status tone-lease" role="status">
        <i aria-hidden="true" /> Enforcing under lease until {new Date(leaseUntil).toLocaleTimeString()}
      </span>
    );
  }
  if (!agents) {
    return (
      <span className="overview-status tone-idle" role="status">
        <i aria-hidden="true" /> Waiting for node agents
      </span>
    );
  }
  const tone = stale > 0 ? 'warn' : 'ok';
  return (
    <span className={`overview-status tone-${tone}`} role="status">
      <i aria-hidden="true" /> Observing · {agents} agent{agents === 1 ? '' : 's'}
      {stale > 0 ? ` · ${stale} stale` : ''}
    </span>
  );
}

function Chapter({
  eyebrow,
  title,
  tone,
  children,
  figures,
  link,
  onOpen,
  flip,
}: {
  eyebrow: string;
  title: string;
  tone: Tone;
  children: ReactNode;
  figures: ReactNode;
  link: string;
  onOpen?: () => void;
  flip?: boolean;
}) {
  return (
    <Reveal>
      <section className={`overview-chapter${flip ? ' overview-chapter--flip' : ''}`}>
        <div className="overview-chapter__copy">
          <p className="apple-eyebrow">
            <span className={`overview-tone tone-${tone}`} aria-hidden="true" />
            {eyebrow}
          </p>
          <h2>{title}</h2>
          {children}
          {onOpen && (
            <button type="button" className="overview-link" onClick={onOpen}>
              {link} ›
            </button>
          )}
        </div>
        <div className="metrics overview-chapter__figures">{figures}</div>
      </section>
    </Reveal>
  );
}

function Signals({ items }: { items: any[] }) {
  if (!items.length) return null;
  return (
    <ul className="overview-signals">
      {items.slice(0, 3).map((a: any, i: number) => (
        <li key={(a.kind || '') + (a.subject || '') + i}>
          <span className={`severity-badge ${a.severity || 'info'}`}>{a.severity || 'info'}</span> {a.message || a.kind}
        </li>
      ))}
    </ul>
  );
}

function Ranked({ title, items, empty, prefix }: { title: string; items: { name: string; count: number }[]; empty: string; prefix?: string }) {
  const top = items.slice(0, 6);
  const max = Math.max(1, ...top.map((x) => x.count || 0));
  return (
    <div className="overview-ranked">
      <h3>{title}</h3>
      {!top.length && <p className="overview-ranked__empty">{empty}</p>}
      <ol>
        {top.map((x) => (
          <li key={x.name}>
            <span className="overview-ranked__bar" style={{ width: `${Math.max(3, (x.count / max) * 100)}%` }} aria-hidden="true" />
            <span className="overview-ranked__name" title={x.name}>
              {prefix}
              {x.name}
            </span>
            <span className="overview-ranked__count">{compact(x.count)}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

export default function Overview({ onNavigate }: { onNavigate?: Navigate }) {
  const { status: data, obs, health, l7, insights, path, drops, features: featSummary, err, rates, history } = useOverviewPulse();
  const go = (p: Page) => (onNavigate ? () => onNavigate(p) : undefined);

  const fp = data?.fastPath;
  const hs = health?.summary || {};
  const ls = l7?.summary || {};
  const ps = path?.summary || {};
  const ds = drops?.summary || {};
  const ins = insights || {};
  const agents = data?.agents ?? 0;
  const stale = data?.staleAgents ?? 0;
  const healthAnoms = hs.anomalies || [];
  const pathAnoms = ps.anomalies || [];
  const dropAnoms = ds.anomalies || [];
  const score = typeof hs.healthScore === 'number' ? hs.healthScore : undefined;

  const healthTone: Tone = score === undefined ? 'idle' : healthAnoms.length || score < 80 ? 'warn' : 'ok';
  const healthTitle =
    score === undefined
      ? 'Waiting for TCP and DNS samples.'
      : healthAnoms.length
        ? `${healthAnoms.length} health signal${healthAnoms.length === 1 ? '' : 's'} need a look.`
        : `Health ${score}/100. Nothing out of line.`;

  const congested = ps.congestedFlows ?? 0;
  const lossy = (ps.lostOut ?? 0) + (ps.retransOut ?? 0);
  const pathTone: Tone = !path ? 'idle' : congested || pathAnoms.length ? 'warn' : 'ok';
  const pathTitle = congested
    ? `${congested.toLocaleString()} flow${congested === 1 ? '' : 's'} under congestion pressure.`
    : pathAnoms.length
      ? `${pathAnoms.length} path signal${pathAnoms.length === 1 ? '' : 's'} raised.`
      : 'Connects are clean.';

  const kernelDrops = ds.kernelDropEvents ?? 0;
  const dropTone: Tone = !drops ? 'idle' : kernelDrops || dropAnoms.length ? 'warn' : 'ok';
  const dropTitle = kernelDrops ? `${kernelDrops.toLocaleString()} kernel drops recorded.` : 'No packets going missing.';

  const drift = (ins.driftFindings ?? 0) + (ins.rateDriftFindings ?? 0);
  const behaviorTone: Tone = !insights ? 'idle' : drift || ins.highExposure ? 'warn' : 'ok';
  const behaviorTitle = drift
    ? `${drift.toLocaleString()} behavior change${drift === 1 ? '' : 's'} to review.`
    : ins.highExposure
      ? `${ins.highExposure} workload${ins.highExposure === 1 ? '' : 's'} highly exposed.`
      : 'Behavior matches what Netra learned.';

  const tls = ls.tlsHandshakes ?? 0;
  const http = ls.httpRequests ?? 0;
  const l7Tone: Tone = !l7 ? 'idle' : (ls.connectBlocked ?? 0) > 0 ? 'warn' : 'ok';
  const l7Title = tls || http ? `${compact(tls + http)} named connections.` : 'TLS and HTTP, named — no payloads.';

  const series = (k: 'packets' | 'bytes' | 'dns' | 'blocked') => history.map((h) => h[k]);

  return (
    <div className="overview">
      <header className="hero">
        <p className="eyebrow">STANDALONE eBPF DATAPATH</p>
        <h1>See the network. Diagnose it. Contain it.</h1>
        <p>
          Netra runs its own eBPF datapath for workload flows, TCP health, DNS timing, socket identity, and leased emergency
          controls.
        </p>
        <div className="overview-hero-row">
          <StatusPill agents={agents} stale={stale} leaseUntil={fp?.enforceUntil} />
          {onNavigate && (
            <>
              <button type="button" className="primary" onClick={go('connections')}>
                Investigate connections
              </button>
              <button type="button" className="overview-link" onClick={go('ebpf')}>
                Open Firewall ›
              </button>
            </>
          )}
        </div>
      </header>

      {fp?.enforceUntil && <p className="warning">Enforcement lease expires {new Date(fp.enforceUntil).toLocaleString()}.</p>}
      {stale > 0 && (
        <p className="warning">
          One or more agents are stale. Each node independently fails back to observe mode after its controller timeout.
        </p>
      )}

      <section className="overview-stage" aria-labelledby="overview-stage-title">
        <div className="overview-stage__head">
          <h2 id="overview-stage-title">The datapath, live.</h2>
          <span className="overview-live">
            <i aria-hidden="true" /> refreshes every {PULSE_INTERVAL_MS / 1000}s
          </span>
        </div>
        <DatapathHero
          workloads={obs?.topWorkloads || []}
          hooks={obs?.hooks || {}}
          agents={agents}
          packetsPerSecond={rates?.packets}
          blockedPerSecond={rates?.blocked}
        />
        <div className="overview-pulse">
          <PulseFigure label="packets / s" value={rates?.packets} format={compact} series={series('packets')} />
          <PulseFigure label="throughput" value={rates?.bytes} format={bytesRate} series={series('bytes')} />
          <PulseFigure label="DNS queries / s" value={rates?.dns} format={compact} series={series('dns')} />
          <PulseFigure
            label="blocked / s"
            value={rates?.blocked}
            format={compact}
            series={series('blocked')}
            tone={(rates?.blocked ?? 0) > 0 ? 'warn' : undefined}
          />
        </div>
        <div className="metrics overview-totals">
          <Metric value={agents} label="node agents" />
          <Metric value={obs?.packets ?? 0} label="packets counted" />
          <Metric value={obs?.blocked ?? 0} label="blocked packets" />
          <Metric value={obs?.dnsQueries ?? 0} label="DNS events" />
          <Metric value={featSummary?.on ?? '—'} label="features on" />
        </div>
      </section>

      <Chapter eyebrow="Network health" title={healthTitle} tone={healthTone} link="Open Network Health" onOpen={go('health')}
        figures={
          <>
            <Metric value={score ?? '—'} label="health score /100" />
            <Metric value={hs.tcpConnections ?? 0} label="TCP connections" />
            <Metric value={hs.estimatedConnectFailures ?? 0} label="est. TCP failures" />
            <Metric value={hs.dnsFailures ?? 0} label="DNS failures" />
          </>
        }
      >
        <p>Sockops and packet hooks time every TCP connect and cleartext DNS answer, straight from the kernel.</p>
        <Signals items={healthAnoms} />
      </Chapter>

      <Chapter eyebrow="L7 metadata" title={l7Title} tone={l7Tone} link="Open L7 Metadata" onOpen={go('l7')} flip
        figures={
          <>
            <Metric value={tls} label="TLS SNI" />
            <Metric value={http} label="HTTP/1 requests" />
            <Metric value={ls.connectAttempts ?? 0} label="socket attempts" />
            <Metric value={ls.connectBlocked ?? 0} label="blocked attempts" />
          </>
        }
      >
        <p>Best-effort SNI and HTTP Host from the datapath. Evidence for review, never a proxy.</p>
      </Chapter>

      <Chapter eyebrow="Path diagnostics" title={pathTitle} tone={pathTone} link="Open Path Diagnostics" onOpen={go('path')}
        figures={
          <>
            <Metric value={ps.connectionsMeasured ?? 0} label="connects timed" />
            <Metric value={congested} label="cwnd-pressure flows" />
            <Metric value={lossy} label="lost + retrans out" />
            <Metric value={pathAnoms.length} label="path signals" />
          </>
        }
      >
        <p>Measured TCP establishment and congestion-window pressure, observe-only.</p>
        <Signals items={pathAnoms} />
      </Chapter>

      <Chapter eyebrow="Drop diagnostics" title={dropTitle} tone={dropTone} link="Open Drop Diagnostics" onOpen={go('drops')} flip
        figures={
          <>
            <Metric value={kernelDrops} label="kernel drop events" />
            <Metric value={ds.softnetDropped ?? 0} label="softnet dropped" />
            <Metric value={(ds.rxDropped ?? 0) + (ds.txDropped ?? 0)} label="iface rx+tx drops" />
            <Metric value={dropAnoms.length} label="drop signals" />
          </>
        }
      >
        <p>Kernel skb reasons, softnet pressure and interface counters, per node.</p>
        <Signals items={dropAnoms} />
      </Chapter>

      <Chapter eyebrow="Behavior insights" title={behaviorTitle} tone={behaviorTone} link="Open Insights" onOpen={go('insights')}
        figures={
          <>
            <Metric value={ins.dependencyEdges ?? 0} label="dependency edges" />
            <Metric value={ins.driftFindings ?? 0} label="behavior drift" />
            <Metric value={ins.rateDriftFindings ?? 0} label="rate anomalies" />
            <Metric value={ins.highExposure ?? 0} label="high exposure" />
          </>
        }
      >
        <p>Baselines and drift from exact eBPF counters. Drafts are review-only; Netra never auto-enforces learned policy.</p>
      </Chapter>

      <Reveal>
        <section className="overview-talking" aria-labelledby="overview-talking-title">
          <div className="overview-stage__head">
            <h2 id="overview-talking-title">Who is talking.</h2>
            {onNavigate && (
              <button type="button" className="overview-link" onClick={go('talkers')}>
                Open Talkers ›
              </button>
            )}
          </div>
          <div className="overview-talking__grid">
            <Ranked title="Destinations" items={obs?.topDestinations || []} empty="No destinations observed yet." />
            <Ranked title="DNS names" items={obs?.topDns || []} empty="No cleartext DNS observed yet." />
            <Ranked title="Processes" items={obs?.topProcesses || []} empty="No socket processes observed yet." />
          </div>
        </section>
      </Reveal>

      <Reveal>
        <section className="overview-platform" aria-label="Datapath capabilities">
          {err && <p className="warning">{err}</p>}
          <ul>
            <li><span>Datapath</span><b>{data?.datapath || '—'}</b></li>
            <li><span>Fast path</span><b>{fp?.mode || '—'}</b></li>
            <li><span>Cilium</span><b>{data?.ciliumRequired ? 'Required' : 'Optional'}</b></li>
            <li><span>Hubble</span><b>{data?.hubble ? 'Enabled' : 'Disabled'}</b></li>
            <li><span>Blocked reasons</span><b>{(obs?.blockReasons || []).length ? obs.blockReasons.slice(0, 2).map((x: any) => `${x.name} · ${x.count}`).join(', ') : 'none'}</b></li>
          </ul>
        </section>
      </Reveal>

      <div className="grid overview-ask">
        <AskNetra />
      </div>

      <p className="overview-closing">
        Cilium is an integration, not a dependency. With Cilium or Hubble installed, Netra can build CiliumNetworkPolicy and
        show Hubble flows — the standalone eBPF engine never depends on them.
      </p>
    </div>
  );
}
