import type {ReactNode} from 'react';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './resources.module.css';

type Asset = {
  title: string;
  blurb: string;
  pages: string;
  files: {label: string; href: string}[];
};

const ASSETS: Asset[] = [
  {
    title: 'Netra Product Perspective',
    blurb:
      '14-page executive deck: how Netra observes, diagnoses, and contains — with pictorial diagrams. Netra-only buyer view.',
    pages: '14 pages · PPTX + PDF',
    files: [
      {label: 'Download PDF', href: '/sales/Zyvor-Netra-Product-Perspective.pdf'},
      {label: 'Download PPTX', href: '/sales/Zyvor-Netra-Product-Perspective.pptx'},
    ],
  },
  {
    title: 'Netra Product Brochure',
    blurb:
      'Longer brochure covering every major capability, lab UI examples, and Zyvor suite placement next to PacketWolf.',
    pages: '12 pages · DOCX + PDF',
    files: [
      {label: 'Download PDF', href: '/sales/Zyvor-Netra-Product-Brochure.pdf'},
      {label: 'Download DOCX', href: '/sales/Zyvor-Netra-Product-Brochure.docx'},
    ],
  },
];

function FileLink({label, href}: {label: string; href: string}) {
  const url = useBaseUrl(href);
  // Plain <a> for static binaries — Docusaurus Link treats them as routes
  // and fails the broken-links check even when the files are in /static.
  return (
    <a className="button button--primary button--sm" href={url} download>
      {label}
    </a>
  );
}

function AssetCard({asset}: {asset: Asset}) {
  return (
    <article className={styles.card}>
      <Heading as="h2" className={styles.cardTitle}>
        {asset.title}
      </Heading>
      <p className={styles.meta}>{asset.pages}</p>
      <p className={styles.blurb}>{asset.blurb}</p>
      <div className={styles.actions}>
        {asset.files.map((f) => (
          <FileLink key={f.href} label={f.label} href={f.href} />
        ))}
      </div>
    </article>
  );
}

export default function Resources(): ReactNode {
  return (
    <Layout
      title="Resources"
      description="Download Netra product perspective and brochure PDFs for buyers and operators.">
      <main className="container margin-vert--lg">
        <header className={styles.header}>
          <Heading as="h1">Resources</Heading>
          <p className={styles.lead}>
            Customer-facing Netra materials — same Zyvor perspective visual
            system. Use these for evaluation, internal buy-in, or sales
            handoffs. For technical docs, see the{' '}
            <Link to="/docs/getting-started/quickstart">quickstart</Link>.
          </p>
        </header>
        <div className={styles.grid}>
          {ASSETS.map((a) => (
            <AssetCard key={a.title} asset={a} />
          ))}
        </div>
        <p className={styles.note}>
          Questions?{' '}
          <a href="mailto:sales@zyvor.dev">sales@zyvor.dev</a>
          {' · '}
          <a href="https://zyvor.dev" target="_blank" rel="noreferrer">
            zyvor.dev
          </a>
        </p>
      </main>
    </Layout>
  );
}
