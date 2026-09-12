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

import { checkCredentials, logout } from './auth';

describe('auth', () => {
  beforeEach(() => {
    store.clear();
  });

  afterEach(() => {
    store.clear();
  });

  it('returns the API token for valid credentials', () => {
    expect(checkCredentials('admin', 'Admin@321')).toBe('Admin@321');
  });

  it('rejects a wrong username', () => {
    expect(checkCredentials('nobody', 'Admin@321')).toBeNull();
  });

  it('rejects a wrong password', () => {
    expect(checkCredentials('admin', 'wrong')).toBeNull();
  });

  it('rejects both wrong', () => {
    expect(checkCredentials('nobody', 'wrong')).toBeNull();
  });

  it('logout clears the stored token', () => {
    store.set('netra-token', 'Admin@321');
    logout();
    expect(store.get('netra-token')).toBeUndefined();
  });
});
