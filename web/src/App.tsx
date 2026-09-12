import { useEffect, useState } from 'react';
import Nav, { Page } from './components/Nav';
import Overview from './pages/Overview';
import Path from './pages/Path';
import Drops from './pages/Drops';
import Insights from './pages/Insights';
import L7 from './pages/L7';
import Policies from './pages/Policies';
import Flows from './pages/Flows';
import EBPF from './pages/EBPF';
import Health from './pages/Health';
import Audit from './pages/Audit';
import Workloads from './pages/Workloads';
import PageHero from './components/PageHero';
import Login from './components/Login';
import { token } from './api';
import { logout } from './auth';
import { applyTheme, readStoredTheme, toggleTheme, type Theme } from './theme';

const pageHero: Partial<Record<Page, { eyebrow: string; title: string; lede: string }>> = {
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
  },
  path: {
    eyebrow: 'Path Diagnostics',
    title: 'Connect latency and pressure.',
    lede: 'Measured active TCP establishment and cwnd/packets-out pressure from standalone sockops.',
  },
  drops: {
    eyebrow: 'Drop Diagnostics',
    title: 'Where packets disappear.',
    lede: 'Kernel skb reasons, softnet pressure, interface counters, and Netra policy-drop detective findings.',
  },
  l7: {
    eyebrow: 'L7 Metadata',
    title: 'TLS and cleartext HTTP context.',
    lede: 'Best-effort SNI and HTTP Host from the datapath — evidence for review, not a full proxy.',
  },
  insights: {
    eyebrow: 'Insights',
    title: 'Behavior, rates, and exposure.',
    lede: 'Baselines, drift, and review-only remediation proposals derived from exact eBPF counters.',
  },
  ebpf: {
    eyebrow: 'Firewall',
    title: 'Observe everywhere. Enforce when leased.',
    lede: 'Every configured rule in one place — deny lists, DDoS shield, and NetPol — plus emergency controls. Netra owns only /sys/fs/bpf/netra.',
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
  },
};

export default function App() {
  const [page, setPage] = useState<Page>('overview');
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

  if (!loggedIn) return <Login onLogin={() => setLoggedIn(true)} />;

  const body = {
    overview: <Overview />,
    pods: <Workloads kind="pod" />,
    vms: <Workloads kind="vm" />,
    health: <Health />,
    path: <Path />,
    drops: <Drops />,
    l7: <L7 />,
    insights: <Insights />,
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
          hero && <PageHero eyebrow={hero.eyebrow} title={hero.title} lede={hero.lede} />
        )}
        {body}
      </main>
    </>
  );
}
