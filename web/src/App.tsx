import { useState } from 'react';
import Nav, { Page } from './components/Nav';
import Overview from './pages/Overview';
import Policies from './pages/Policies';
import Flows from './pages/Flows';
import EBPF from './pages/EBPF';
import Audit from './pages/Audit';
import Workloads from './pages/Workloads';
import { setToken, token } from './api';

export default function App() {
  const [page, setPage] = useState<Page>('overview');
  const [tok, setTok] = useState(token());
  const body = {
    overview: <Overview />,
    pods: <Workloads kind="pod" />,
    vms: <Workloads kind="vm" />,
    policies: <Policies />,
    flows: <Flows />,
    ebpf: <EBPF />,
    audit: <Audit />,
  }[page];
  return (
    <>
      <Nav page={page} setPage={setPage} />
      <main>
        <header className="hero">
          <div>
            <p className="eyebrow">CILIUM OPERATIONS</p>
            <h1>See egress. Shape policy. Contain fast.</h1>
            <p>One operator surface for CiliumNetworkPolicy, Hubble Relay and an isolated Zyvor eBPF emergency path.</p>
          </div>
          <label className="tokenbox">
            API token
            <input
              type="password"
              value={tok}
              placeholder="required unless dev mode"
              onChange={(e) => {
                setTok(e.target.value);
                setToken(e.target.value);
              }}
            />
          </label>
        </header>
        {body}
      </main>
    </>
  );
}
