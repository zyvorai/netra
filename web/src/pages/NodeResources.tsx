import { useEffect, useState } from 'react';
import { api } from '../api';

const gb = (b: number | undefined) => ((b || 0) / (1024 ** 3)).toFixed(1);
const pct = (n: number | undefined) => `${(n || 0).toFixed(0)}%`;
const dur = (sec: number) => sec < 60 ? `${Math.round(sec)}s` : sec < 3600 ? `${Math.round(sec / 60)}m` : sec < 86400 ? `${(sec / 3600).toFixed(1)}h` : `${(sec / 86400).toFixed(1)}d`;

export default function NodeResources() {
  const [data, setData] = useState<any>();
  const [err, setErr] = useState('');
  const load = () => api<any>('/api/v1/node-resources?limit=50')
    .then((d) => { setData(d); setErr(''); })
    .catch((e) => setErr(String(e)));
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);

  const s = data?.summary || {};
  const nodes = data?.nodes || [];
  const topWorkloads = data?.topWorkloadsByCpu || [];

  return <div className="grid">
    {err && <section className="card span3"><p className="warning">{err}</p></section>}

    <section className="card span3">
      <p className="eyebrow">CLUSTER PULSE</p>
      <div className="metrics">
        <div><b>{s.nodes || 0}</b><span>nodes</span></div>
        <div><b>{pct(s.avgCpuPercent)}</b><span>avg CPU</span></div>
        <div><b>{gb(s.usedMemoryBytes)} / {gb(s.totalMemoryBytes)} GB</b><span>memory used/total</span></div>
        <div><b>{s.totalCpuCores || 0}</b><span>total cores</span></div>
        <div><b>{s.highestCpuNode || '—'}</b><span>highest CPU node</span></div>
        <div><b>{s.highestMemoryNode || '—'}</b><span>highest memory node</span></div>
      </div>
      <p>A "top"-like snapshot: host CPU/memory/load average per node, plus per-workload cgroup v2 usage attributed to pods/containers rather than raw PIDs. {(data?.limitations || []).join(' ')}</p>
    </section>

    <section className="card span3">
      <p className="eyebrow">PER-NODE</p>
      <h3>Host CPU, memory, and load</h3>
      {nodes.length === 0 && <p className="empty-state">No agent reports yet.</p>}
      {nodes.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>NODE</span><span>CPU</span><span>LOAD 1 / 5 / 15</span><span>MEMORY</span><span>UPTIME</span></div>
        {nodes.map((n: any) => (
          <div className="datarow obs" key={n.node}>
            <span className="truncate" title={n.node}>
              {n.node} {n.stale && <span className="severity-badge warning">stale</span>}
            </span>
            <span>{pct(n.host?.cpuPercent)} · {n.host?.cpuCores || 0} cores</span>
            <span>{(n.host?.loadAvg1 || 0).toFixed(2)} / {(n.host?.loadAvg5 || 0).toFixed(2)} / {(n.host?.loadAvg15 || 0).toFixed(2)}</span>
            <span>{gb(n.host?.memoryUsedBytes)} / {gb(n.host?.memoryTotalBytes)} GB</span>
            <span>{n.host?.uptimeSeconds ? dur(n.host.uptimeSeconds) : '—'}</span>
          </div>
        ))}
      </div>}
    </section>

    <section className="card span3">
      <p className="eyebrow">TOP WORKLOADS</p>
      <h3>Highest CPU usage, cgroup v2-attributed</h3>
      {topWorkloads.length === 0 && <p className="empty-state">No workload resource samples yet.</p>}
      {topWorkloads.length > 0 && <div className="datatable-scroll">
        <div className="datahead obs"><span>WORKLOAD</span><span>NODE</span><span>CPU</span><span>MEMORY</span></div>
        {topWorkloads.map((w: any, i: number) => {
          const who = w.namespace ? `${w.namespace}/${w.pod}` : (w.workloadName || `cgroup ${w.cgroupId || 0}`);
          return <div className="datarow obs" key={i}>
            <span className="truncate" title={who} aria-label={who}>{who}{w.workloadKind ? ` · ${w.workloadKind}` : ''}</span>
            <span>{w.node}</span>
            <span>{pct(w.cpuPercent)}</span>
            <span>{gb(w.memoryUsedBytes)} GB{w.memoryLimitBytes ? ` / ${gb(w.memoryLimitBytes)} GB` : ''}</span>
          </div>;
        })}
      </div>}
    </section>
  </div>;
}
