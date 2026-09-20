// Frontend-only login gate over Netra's single shared-bearer-token backend
// model (internal/api/server.go: Server.apiKey / bearer() / auth() — there is
// no per-user backend concept). Friendly username+password maps to the
// bearer the server accepts. Deploy/Helm often mint a random NETRA_API_KEY;
// operators can sign in as admin with that key as the password. The demo
// pair admin / Admin@321 still maps to the baked-in demo token.
import { clearSession } from './api';

const USERNAME = 'admin';
const PASSWORD = 'Admin@321';
/** Demo bearer — keep in sync with default lab/deploy NETRA_API_KEY. */
const API_TOKEN = 'Admin@321';

/**
 * Bearer tokens to try for this login, in order.
 * Empty means reject before any network call (wrong username / empty password).
 */
export function bearerCandidates(username: string, password: string): string[] {
  if (username !== USERNAME || password === '') return [];
  const out: string[] = [];
  if (password === PASSWORD) out.push(API_TOKEN);
  if (!out.includes(password)) out.push(password);
  return out;
}

/** @deprecated Prefer bearerCandidates + a live probe; kept for unit tests. */
export function checkCredentials(username: string, password: string): string | null {
  const c = bearerCandidates(username, password);
  return c[0] ?? null;
}

export function logout(): void {
  clearSession();
}
