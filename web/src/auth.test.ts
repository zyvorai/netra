import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const store = new Map<string, string>();

vi.stubGlobal('localStorage', {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => {
    store.set(k, v);
  },
  removeItem: (k: string) => {
    store.delete(k);
  },
});

import { bearerCandidates, checkCredentials, logout } from './auth';

describe('auth', () => {
  beforeEach(() => {
    store.clear();
  });

  afterEach(() => {
    store.clear();
  });

  it('returns the demo API token for default credentials', () => {
    expect(checkCredentials('admin', 'Admin@321')).toBe('Admin@321');
    expect(bearerCandidates('admin', 'Admin@321')).toEqual(['Admin@321']);
  });

  it('treats a non-demo password as a NETRA_API_KEY candidate', () => {
    expect(bearerCandidates('admin', 'deadbeef')).toEqual(['deadbeef']);
  });

  it('rejects a wrong username', () => {
    expect(checkCredentials('nobody', 'Admin@321')).toBeNull();
    expect(bearerCandidates('nobody', 'Admin@321')).toEqual([]);
  });

  it('rejects empty password', () => {
    expect(bearerCandidates('admin', '')).toEqual([]);
  });

  it('logout clears the stored token', () => {
    store.set('netra-token', 'Admin@321');
    logout();
    expect(store.get('netra-token')).toBeUndefined();
  });
});
