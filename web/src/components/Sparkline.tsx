// A small inline-SVG trend line, no npm dependency — reagraph (the only
// chart lib in this repo) is a force-directed graph library, the wrong
// tool for a fixed sequence of points. Kept deliberately minimal: last N
// values, no axes/labels/tooltips.
export default function Sparkline({ values, width = 160, height = 32 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 0.0001);
  const points = values.map((v, i) => `${(i / (values.length - 1)) * width},${height - (v / max) * height}`).join(' ');
  return (
    <svg width={width} height={height} className="sparkline" role="img" aria-label="trend">
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}
