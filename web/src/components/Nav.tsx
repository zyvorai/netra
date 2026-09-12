import type { Theme } from '../theme';

export type Page =
  | 'overview'
  | 'pods'
  | 'vms'
  | 'health'
  | 'path'
  | 'drops'
  | 'l7'
  | 'insights'
  | 'policies'
  | 'flows'
  | 'ebpf'
  | 'audit';

const items: [Page, string][] = [
  ['overview', 'Overview'],
  ['pods', 'Pods'],
  ['vms', 'VMs'],
  ['health', 'Health'],
  ['path', 'Path'],
  ['drops', 'Drops'],
  ['l7', 'L7'],
  ['insights', 'Insights'],
  ['ebpf', 'Firewall'],
  ['flows', 'Hubble'],
  ['policies', 'Policies'],
  ['audit', 'Audit'],
];

export default function Nav({
  page,
  setPage,
  theme,
  onToggleTheme,
  onLogout,
}: {
  page: Page;
  setPage: (p: Page) => void;
  theme: Theme;
  onToggleTheme: () => void;
  onLogout: () => void;
}) {
  return (
    <nav className="nav" aria-label="Global">
      <div className="nav-inner">
        <button type="button" className="brand" onClick={() => setPage('overview')} aria-label="Netra home">
          <img src="/zyvor-logomark.svg" alt="" className="brand-mark" aria-hidden />
          Netra
        </button>
        <div className="navlinks">
          {items.map(([id, label]) => (
            <button
              key={id}
              type="button"
              className={page === id ? 'active' : ''}
              aria-current={page === id ? 'page' : undefined}
              onClick={() => setPage(id)}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="nav-actions">
          <button type="button" className="theme-toggle" onClick={onLogout} aria-label="Log out" title="Log out">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
              <path d="M15 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M10 12h11m0 0-3.5-3.5M21 12l-3.5 3.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </button>
          <button
            type="button"
            className="theme-toggle"
            onClick={onToggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            title={theme === 'dark' ? 'Light' : 'Dark'}
          >
            {theme === 'dark' ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
                <path d="M21 14.5A8.5 8.5 0 1 1 11.5 3a7 7 0 0 0 9.5 11.5z" />
              </svg>
            )}
          </button>
        </div>
      </div>
    </nav>
  );
}
