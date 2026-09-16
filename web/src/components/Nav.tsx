import { useEffect, useRef, useState } from 'react';
import type { Theme } from '../theme';
import DigestChip from './DigestChip';

export type Page =
  | 'overview'
  | 'connections'
  | 'workloads'
  | 'explain'
  | 'pods'
  | 'vms'
  | 'health'
  | 'path'
  | 'drops'
  | 'l7'
  | 'insights'
  | 'topology'
  | 'incidents'
  | 'policies'
  | 'flows'
  | 'ebpf'
  | 'audit'
  | 'report'
  | 'scorecard'
  | 'talkers'
  | 'fleet'
  | 'traffic'
  | 'capture'
  | 'congestion';

type NavLink = { page: Page; label: string; blurb: string };
type NavGroup = { label: string; page?: Page; children?: NavLink[] };

// Blurbs are the same copy as each page's own pageHero lede in App.tsx,
// kept in sync by hand since there's no shared source for the two today.
const groups: NavGroup[] = [
  { label: 'Overview', page: 'overview' },
  {
    label: 'Investigate',
    children: [
      { page: 'connections', label: 'Connections', blurb: 'Native eBPF events, workload context, and honest explanations of observed outcomes.' },
      { page: 'workloads', label: 'Workloads', blurb: 'Explore identities and network evidence reported by Netra agents.' },
      { page: 'pods', label: 'Pods', blurb: 'Kubernetes workloads resolved from Netra’s cgroup map.' },
      { page: 'vms', label: 'VMs', blurb: 'KubeVirt and host VMM processes Netra can attribute.' },
      { page: 'explain', label: 'Explain', blurb: 'Passive, read-only evidence from agent reports, one selector away.' },
      { page: 'traffic', label: 'Traffic', blurb: 'Namespace, protocol, port, and DNS breakdowns. No payloads.' },
      { page: 'capture', label: 'Capture', blurb: 'Filtered, time-bounded packet capture per node, live.' },
    ],
  },
  {
    label: 'Diagnostics',
    children: [
      { page: 'health', label: 'Health', blurb: 'RTT, retransmits, RTOs, resets, and cleartext DNS latency from the kernel.' },
      { page: 'path', label: 'Path', blurb: 'Measured active TCP establishment and cwnd/packets-out pressure.' },
      { page: 'drops', label: 'Drops', blurb: 'Kernel skb reasons, softnet pressure, policy-drop findings, and windowed kernel-network diagnostics — see also Congestion Map for where in the stack.' },
      { page: 'congestion', label: 'Congestion Map', blurb: 'A pictorial view of the Linux network stack, colored by where the cluster is congested right now.' },
      { page: 'l7', label: 'L7', blurb: 'Best-effort SNI and HTTP Host from the datapath.' },
      { page: 'insights', label: 'Insights', blurb: 'Baselines, drift, and review-only remediation proposals.' },
      { page: 'topology', label: 'Topology', blurb: 'The observed-traffic dependency graph, live and force-directed.' },
    ],
  },
  {
    label: 'Security',
    children: [
      { page: 'incidents', label: 'Incidents', blurb: 'Health, drift, exposure, drops, and audit signals joined by shared source.' },
      { page: 'ebpf', label: 'Firewall', blurb: 'Deny lists, DDoS shield, NetPol, and emergency controls in one place.' },
      { page: 'policies', label: 'Policies', blurb: 'Plan and apply CiliumNetworkPolicy when CRDs are present.' },
      { page: 'audit', label: 'Audit', blurb: 'Controller audit trail for policy and datapath actions.' },
    ],
  },
  {
    label: 'Reports',
    children: [
      { page: 'flows', label: 'Hubble', blurb: 'Optional Cilium enrichment when Hubble Relay is available.' },
      { page: 'report', label: 'Report', blurb: 'A point-in-time health, drift, and incident briefing.' },
      { page: 'scorecard', label: 'Scorecard', blurb: 'Health, stale agents, and blocked events folded into a 0–100 board.' },
      { page: 'talkers', label: 'Talkers', blurb: 'Top destination IPs by packet count. No payloads.' },
    ],
  },
  { label: 'Fleet', page: 'fleet' },
];

const OPEN_DELAY_MS = 120;
const CLOSE_DELAY_MS = 450;

export default function Nav({
  page,
  setPage,
  theme,
  onToggleTheme,
  onLogout,
}: {
  page: Page;
  setPage: (p: Page) => void;
  theme: Theme;
  onToggleTheme: () => void;
  onLogout: () => void;
}) {
  const [openGroup, setOpenGroup] = useState<string | null>(null);
  const openTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const navRef = useRef<HTMLElement | null>(null);
  const triggerRefs = useRef<Record<string, HTMLButtonElement | null>>({});

  const clearTimers = () => {
    if (openTimer.current) clearTimeout(openTimer.current);
    if (closeTimer.current) clearTimeout(closeTimer.current);
    openTimer.current = null;
    closeTimer.current = null;
  };

  const scheduleOpen = (label: string) => {
    clearTimers();
    openTimer.current = setTimeout(() => setOpenGroup(label), OPEN_DELAY_MS);
  };

  const scheduleClose = () => {
    clearTimers();
    closeTimer.current = setTimeout(() => setOpenGroup(null), CLOSE_DELAY_MS);
  };

  const toggleGroup = (label: string) => {
    clearTimers();
    setOpenGroup((cur) => (cur === label ? null : label));
  };

  useEffect(() => () => clearTimers(), []);

  useEffect(() => {
    if (!openGroup) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const label = openGroup;
      setOpenGroup(null);
      triggerRefs.current[label]?.focus();
    };
    const onPointerDown = (e: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(e.target as Node)) setOpenGroup(null);
    };
    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('mousedown', onPointerDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('mousedown', onPointerDown);
    };
  }, [openGroup]);

  return (
    <nav className="nav" aria-label="Global" ref={navRef}>
      <div className="nav-inner">
        <button type="button" className="brand" onClick={() => setPage('overview')} aria-label="Netra home">
          <img src="/zyvor-logomark.svg" alt="" className="brand-mark" aria-hidden />
          Netra
        </button>
        <div className="navlinks">
          {groups.map((g) =>
            g.children ? (
              <div
                key={g.label}
                className="navgroup"
                onMouseEnter={() => scheduleOpen(g.label)}
                onMouseLeave={scheduleClose}
              >
                <button
                  type="button"
                  ref={(el) => {
                    triggerRefs.current[g.label] = el;
                  }}
                  className={g.children.some((c) => c.page === page) ? 'active' : ''}
                  aria-haspopup="true"
                  aria-expanded={openGroup === g.label}
                  onClick={() => toggleGroup(g.label)}
                >
                  {g.label}
                </button>
                <div
                  className={`mega-panel${openGroup === g.label ? ' open' : ''}`}
                  role="region"
                  aria-label={g.label}
                  onMouseEnter={() => scheduleOpen(g.label)}
                  onMouseLeave={scheduleClose}
                >
                  <div className="mega-grid">
                    {g.children.map((c) => (
                      <button
                        key={c.page}
                        type="button"
                        className={page === c.page ? 'active' : ''}
                        aria-current={page === c.page ? 'page' : undefined}
                        onClick={() => {
                          setPage(c.page);
                          setOpenGroup(null);
                        }}
                      >
                        <span className="mega-link-label">{c.label}</span>
                        <span className="mega-link-blurb">{c.blurb}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <button
                key={g.page}
                type="button"
                className={page === g.page ? 'active' : ''}
                aria-current={page === g.page ? 'page' : undefined}
                onClick={() => setPage(g.page as Page)}
              >
                {g.label}
              </button>
            )
          )}
        </div>
        <div className="nav-actions">
          <DigestChip onOpen={() => setPage('overview')} />
          <button type="button" className="theme-toggle" onClick={onLogout} aria-label="Log out" title="Log out">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
              <path d="M15 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M10 12h11m0 0-3.5-3.5M21 12l-3.5 3.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
          <button
            type="button"
            className="theme-toggle"
            onClick={onToggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            title={theme === 'dark' ? 'Light' : 'Dark'}
          >
            {theme === 'dark' ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
                <path d="M21 14.5A8.5 8.5 0 1 1 11.5 3a7 7 0 0 0 9.5 11.5z" />
              </svg>
            )}
          </button>
        </div>
      </div>
    </nav>
  );
}
