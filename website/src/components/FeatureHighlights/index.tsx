import type {ReactNode} from 'react';
import Link from '@docusaurus/Link';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  description: ReactNode;
  to: string;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'Observability',
    description:
      'Exact flow, TCP health, DNS timing, and workload-attributed socket telemetry from cgroup and socket hooks — no CNI dependency.',
    to: '/docs/core-concepts/architecture',
  },
  {
    title: 'L7 metadata',
    description:
      'Best-effort TLS ClientHello SNI and cleartext HTTP/1 method + Host, metadata-only — no payload capture, no TLS decryption.',
    to: '/docs/security',
  },
  {
    title: 'Behavior & rate insights',
    description:
      'Kubernetes-aware dependency graphs, behavior-baseline drift detection, and review-only policy drafts — never auto-applied.',
    to: '/docs/security',
  },
  {
    title: 'Emergency enforcement',
    description:
      'Exact IP/CIDR/port/UID/process/DNS/SNI deny, workload-scoped, all behind a time-limited lease that fails open by default.',
    to: '/docs/core-concepts/architecture',
  },
  {
    title: 'Optional Cilium & Hubble',
    description:
      'Read Hubble flows and manage CiliumNetworkPolicy when Cilium is present — required by nothing, useful with everything.',
    to: '/docs/core-concepts/architecture',
  },
  {
    title: 'AI agent integration',
    description:
      'netra-mcp exposes the controller API as 89 stdio tools for AI agents, with mutating tools opt-in and off by default.',
    to: 'https://github.com/zyvorai/netra/blob/main/docs/mcp-integration.md',
  },
];

function Feature({title, description, to}: FeatureItem) {
  return (
    <div className="col col--4">
      <Link to={to} className={styles.card}>
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </Link>
    </div>
  );
}

export default function FeatureHighlights(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
