import { useMemo, useState } from 'react';
import InvestigationFilters from '../components/InvestigationFilters';
import ConnectionTable from '../components/ConnectionTable';
import { useRoute, useSnapshot } from '../hooks/useInvestigation';
import { eventRows, type Agent } from '../lib/investigation';
export default function Connections() {
  const [paused, setPaused] = useState(false);
  const { scope } = useRoute();
  const snapshot = useSnapshot<{ items: Agent[] }>('/api/v1/agents', paused);
  const rows = useMemo(() => eventRows(snapshot.data?.items || [], scope), [snapshot.data, scope]);
  return <div className="investigation"><InvestigationFilters /><section className="card"><div className="toolbar"><h2>Native connections</h2><button onClick={() => setPaused(p => !p)}>{paused ? 'Resume updates' : 'Pause updates'}</button><button disabled={paused} onClick={snapshot.refresh}>Refresh</button></div>
    <p>Recent sampled events from Netra agents. Refreshes every 10 seconds. {paused ? 'Updates paused.' : ''}</p>
    {snapshot.updatedAt && <p className="snapshot-time">Last successful fetch: {new Date(snapshot.updatedAt).toLocaleTimeString()}. Event times and agent freshness appear below.</p>}
    {snapshot.error && <p role="alert" className="warning">Refresh failed. Any displayed data is from the last successful fetch. {snapshot.error}</p>}
    {snapshot.loading ? <p role="status">Loading agent reports…</p> : <ConnectionTable rows={rows} />}
  </section></div>;
}
