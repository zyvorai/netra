import LiveFlowTerminal from '../components/LiveFlowTerminal';

export default function Flows() {
  return (
    <div className="grid">
      <section className="card span3">
        <p className="eyebrow">HUBBLE RELAY</p>
        <h2>Live flows</h2>
        <p>Cluster-wide Hubble stream. Open Pods or VMs for per-entity scoped traffic and rules.</p>
      </section>
      <div className="span3">
        <LiveFlowTerminal />
      </div>
    </div>
  );
}
