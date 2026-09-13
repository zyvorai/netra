import { describe, expect, it } from 'vitest';
import { digestLabel } from './DigestChip';

describe('digestLabel', () => {
  it('shows severity and a short fingerprint', () => {
    expect(digestLabel({ severity: 'warning', fingerprint: 'a1b2c3d4e5f6' })).toBe('warning · a1b2c3');
  });

  it('marks a changed incident cluster', () => {
    expect(digestLabel({ severity: 'critical', fingerprint: 'deadbeef0001', changed: true })).toBe(
      'critical · changed deadbe',
    );
  });
});
