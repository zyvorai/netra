import { useEffect, useState } from 'react';
import Nav, { Page } from './components/Nav';
import Overview from './pages/Overview';
import Connections from './pages/Connections';
import ObservedWorkloads from './pages/ObservedWorkloads';
import Explain from './pages/Explain';
import { readRoute } from './lib/investigation';
import Path from './pages/Path';
import Drops from './pages/Drops';
import Insights from './pages/Insights';
import Topology from './pages/Topology';
import L7 from './pages/L7';
import Policies from './pages/Policies';
import Flows from './pages/Flows';
import EBPF from './pages/EBPF';
import Health from './pages/Health';
import Audit from './pages/Audit';
import Workloads from './pages/Workloads';
import PageHero, { type HeroTint } from './components/PageHero';
import Login from './components/Login';
import { token } from './api';
import { logout } from './auth';
import { applyTheme, readStoredTheme, toggleTheme, type Theme } from './theme';

const pageHero: Partial<Record<Page, { eyebrow: string; title: string; lede: string; tint?: HeroTint }>> = {
  connections: {
    eyebrow: 'Investigation',
    title: 'Follow every clue.',
    lede: 'Native eBPF events, workload context, and honest explanations of observed outcomes.',
  },
  workloads: {
    eyebrow: 'Investigation',
    title: 'Know the workload.',
    lede: 'Explore identities and network evidence reported by Netra agents.',
  },
  explain: {
    eyebrow: 'Investigation',
    title: 'Explain a connection.',
    lede: 'Passive, read-only evidence from agent reports — the same diagnostics as netractl explain, one selector away.',
  },
  pods: {
    eyebrow: 'Workloads',
    title: 'Pods.',
    lede: 'Kubernetes workloads resolved from Netra’s cgroup map — identity for observe and leased enforce.',
  },
  vms: {
    eyebrow: 'Workloads',
    title: 'Virtual machines.',
    lede: 'KubeVirt and host VMM processes Netra can attribute through cgroup and process metadata.',
  },
  health: {
    eyebrow: 'Network Health',
    title: 'TCP and DNS from the kernel.',
    lede: 'Sockops and packet hooks measure RTT, retransmits, RTOs, resets, and cleartext DNS latency.',
    tint: 'green',
  },
  path: {
    eyebrow: 'Path Diagnostics',
    title: 'Connect latency and pressure.',
    lede: 'Measured active TCP establishment and cwnd/packets-out pressure from standalone sockops.',
    tint: 'green',
  },
  drops: {
    eyebrow: 'Drop Diagnostics',
    title: 'Where packets disappear.',
    lede: 'Kernel skb reasons, softnet pressure, interface counters, and Netra policy-drop detective findings.',
    tint: 'amber',
  },
  l7: {
    eyebrow: 'L7 Metadata',
    title: 'TLS and cleartext HTTP context.',
    lede: 'Best-effort SNI and HTTP Host from the datapath — evidence for review, not a full proxy.',
    tint: 'amber',
  },
  insights: {
    eyebrow: 'Insights',
    title: 'Behavior, rates, and exposure.',
    lede: 'Baselines, drift, and review-only remediation proposals derived from exact eBPF counters.',
    tint: 'purple',
  },
  topology: {
    eyebrow: 'Insights',
    title: 'See the graph move.',
    lede: 'The same observed-traffic dependency graph, live and force-directed — drift, rate-drift, and exposure findings overlaid as node color.',
    tint: 'purple',
  },
  ebpf: {
    eyebrow: 'Firewall',
    title: 'Observe everywhere. Enforce when leased.',
    lede: 'Every configured rule in one place — deny lists, DDoS shield, and NetPol — plus emergency controls. Netra owns only /sys/fs/bpf/netra.',
    tint: 'red',
  },
  flows: {
    eyebrow: 'Hubble',
    title: 'Optional Cilium enrichment.',
    lede: 'When Hubble Relay is available, enrich the picture. Otherwise use Network Health and eBPF.',
  },
  policies: {
    eyebrow: 'Policies',
    title: 'Cilium workbench.',
    lede: 'Plan and apply CiliumNetworkPolicy when CRDs are present. Standalone eBPF controls work without Cilium.',
  },
  audit: {
    eyebrow: 'Audit',
    title: 'What changed.',
    lede: 'Controller audit trail for policy and datapath actions.',
    tint: 'red',
  },
};

export default function App() {
  // Defaults to 'overview' exactly like plain useState('overview') did when
  // there's no hash — only differs when the URL already carries a shared
  // investigation link (#page=...), so a pasted link opens directly to it.
  const [page, setPage] = useState<Page>(() => readRoute(window.location.hash).page as Page);
  const [loggedIn, setLoggedIn] = useState(() => Boolean(token()));
  const [theme, setTheme] = useState<Theme>(() => {
    const t = readStoredTheme();
    applyTheme(t);
    return t;
  });

  useEffect(() => {
    const onExpired = () => setLoggedIn(false);
    window.addEventListener('netra-auth-expired', onExpired);
    return () => window.removeEventListener('netra-auth-expired', onExpired);
  }, []);

  // Regular Nav clicks call setPage(id) directly and never touch the hash,
  // so existing navigation keeps its exact current behavior (no URL change,
  // no history entry). This listener only exists so the investigation
  // feature's own navigate() calls (which do set the hash, for shareable
  // links) can switch the visible page too.
  useEffect(() => {
    const onHashChange = () => setPage(readRoute(window.location.hash).page as Page);
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  if (!loggedIn) return <Login onLogin={() => setLoggedIn(true)} />;

  const body = {
    overview: <Overview />,
    connections: <Connections />,
    workloads: <ObservedWorkloads />,
    explain: <Explain />,
    pods: <Workloads key="pod" kind="pod" />,
    vms: <Workloads key="vm" kind="vm" />,
    health: <Health />,
    path: <Path />,
    drops: <Drops />,
    l7: <L7 />,
    insights: <Insights />,
    topology: <Topology />,
    policies: <Policies />,
    flows: <Flows />,
    ebpf: <EBPF />,
    audit: <Audit />,
  }[page];

  const hero = pageHero[page];

  return (
    <>
      <Nav
        page={page}
        setPage={setPage}
        theme={theme}
        onToggleTheme={() => setTheme((t) => toggleTheme(t))}
        onLogout={() => {
          logout();
          setLoggedIn(false);
        }}
      />
      <main>
        {/* Keyed on `page` so the hero and body remount (rather than just
            re-render in place) on every navigation, re-triggering their
            fadeRise/glow entrance animations — otherwise PageHero, being
            the same component type at the same tree position across page
            switches, would just update props with no visible transition. */}
        <div key={page}>
          {page === 'overview' ? (
            <header className="hero">
              <div>
                <p className="eyebrow">STANDALONE eBPF DATAPATH</p>
                <h1>See the network. Diagnose it. Contain it.</h1>
                <p>
                  Netra runs its own eBPF datapath for workload flows, TCP health, DNS timing, socket identity, and leased
                  emergency controls.
                </p>
              </div>
            </header>
          ) : (
            hero && <PageHero eyebrow={hero.eyebrow} title={hero.title} lede={hero.lede} tint={hero.tint} />
          )}
          {body}
        </div>
      </main>
    </>
  );
}
