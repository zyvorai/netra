import type {ReactNode} from 'react';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './gallery.module.css';

type Shot = {
  src: string;
  caption: string;
};

// The docs/ux/v022 set is a single deployment's full-page walkthrough,
// already captured in this exact narrative order.
const TOUR: Shot[] = [
  {src: '/v022/00-overview.png', caption: 'Overview'},
  {src: '/v022/01-pods.png', caption: 'Pods'},
  {src: '/v022/02-vms.png', caption: 'VMs (KubeVirt)'},
  {src: '/v022/03-network-health.png', caption: 'Network Health'},
  {src: '/v022/04-path-diagnostics.png', caption: 'Path Diagnostics'},
  {src: '/v022/05-drop-diagnostics.png', caption: 'Drop Diagnostics'},
  {src: '/v022/06-l7-metadata.png', caption: 'L7 Metadata'},
  {src: '/v022/07-insights.png', caption: 'Insights'},
  {src: '/v022/08-ebpf.png', caption: 'Firewall'},
  {src: '/v022/09-hubble.png', caption: 'Hubble live flows'},
  {src: '/v022/10-policies.png', caption: 'Policies'},
  {src: '/v022/11-audit.png', caption: 'Audit'},
];

function ShotCard({shot}: {shot: Shot}) {
  const src = useBaseUrl(shot.src);
  return (
    <figure className={styles.shot}>
      <img src={src} alt={shot.caption} loading="lazy" />
      <figcaption>{shot.caption}</figcaption>
    </figure>
  );
}

export default function Gallery(): ReactNode {
  const gif = useBaseUrl('/netra-live-demo.gif');
  return (
    <Layout
      title="Gallery"
      description="A full walkthrough of the Netra dashboard, captured against a live lab deployment.">
      <header className={styles.header}>
        <div className="container">
          <Heading as="h1">Product tour</Heading>
          <p>
            Every screenshot below is captured against a real, running lab
            deployment — not a mockup.
          </p>
        </div>
      </header>
      <main className="container">
        <div className={styles.demo}>
          <img
            src={gif}
            alt="Netra live demo — Overview, Firewall/NetPol v2, in-browser VNC console"
          />
          <p className={styles.caption}>
            Live demo: Overview, the Firewall page's unified rules table and
            NetPol v2 allow-list, then a real in-browser VNC console
            connected to a running KubeVirt VM.
          </p>
        </div>
        <div className={styles.grid}>
          {TOUR.map((shot) => (
            <ShotCard key={shot.src} shot={shot} />
          ))}
        </div>
      </main>
    </Layout>
  );
}
