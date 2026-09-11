import { Box, Server, Shield, Activity, Network, TerminalSquare, History } from 'lucide-react';

export type Page = 'overview' | 'pods' | 'vms' | 'policies' | 'flows' | 'ebpf' | 'audit';

export default function Nav({ page, setPage }: { page: Page; setPage: (p: Page) => void }) {
  const items: [Page, React.ReactNode, string][] = [
    ['overview', <Activity size={17} />, 'Overview'],
    ['pods', <Box size={17} />, 'Pods'],
    ['vms', <Server size={17} />, 'VMs'],
    ['ebpf', <TerminalSquare size={17} />, 'eBPF'],
    ['flows', <Network size={17} />, 'Hubble'],
    ['policies', <Shield size={17} />, 'Policies'],
    ['audit', <History size={17} />, 'Audit'],
  ];
  return (
    <nav className="nav">
      <div className="brand">
        <span className="dot" />
        NETRA <small>by Zyvor</small>
      </div>
      <div className="navlinks">
        {items.map(([id, icon, label]) => (
          <button key={id} className={page === id ? 'active' : ''} onClick={() => setPage(id)}>
            {icon}
            {label}
          </button>
        ))}
      </div>
    </nav>
  );
}
