// A small inline-SVG trend line, no npm dependency — reagraph (the only
// chart lib in this repo) is a force-directed graph library, the wrong
// tool for a fixed sequence of points. Kept deliberately minimal: last N
// values, no axes/labels/tooltips.
export default function Sparkline({
  values,
  width = 160,
  height = 32,
  fill = false,
}: {
  values: number[];
  width?: number;
  height?: number;
  fill?: boolean;
}) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 0.0001);
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * width},${height - (v / max) * (height - 2) - 1}`);
  const points = pts.join(' ');
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" className="sparkline" role="img" aria-label="trend">
      {fill && <polygon points={`0,${height} ${points} ${width},${height}`} fill="currentColor" opacity="0.12" stroke="none" />}
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}
