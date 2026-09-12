// Frontend-only login gate over Netra's single shared-bearer-token backend
// model (internal/api/server.go: Server.apiKey / bearer() / auth() — there is
// no per-user backend concept). This maps one friendly username+password pair
// to the one bearer token the server accepts, so the API token isn't shown as
// a bare token field in the UI. If the API token is ever rotated independently
// of this login password, update API_TOKEN below — do not scatter these
// literals elsewhere.
import { setToken } from './api';

const USERNAME = 'admin';
const PASSWORD = 'Admin@321';
const API_TOKEN = 'Admin@321';

export function checkCredentials(username: string, password: string): string | null {
  return username === USERNAME && password === PASSWORD ? API_TOKEN : null;
}

export function logout(): void {
  setToken('');
}
