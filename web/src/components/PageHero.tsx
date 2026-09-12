type PageHeroProps = {
  eyebrow: string;
  title: string;
  lede: string;
};

export default function PageHero({ eyebrow, title, lede }: PageHeroProps) {
  return (
    <header className="page-hero">
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
      <p>{lede}</p>
    </header>
  );
}
