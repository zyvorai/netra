import { describe, expect, it } from 'vitest';
import { ASK_SUGGESTIONS, canAsk, looksLikeDraft } from './AskNetra';

describe('AskNetra helpers', () => {
  it('ships a short read-only suggestion set', () => {
    expect(ASK_SUGGESTIONS.length).toBeGreaterThanOrEqual(3);
    expect(ASK_SUGGESTIONS.every((q) => q.length < 80)).toBe(true);
  });

  it('blocks empty or in-flight questions', () => {
    expect(canAsk('', false)).toBe(false);
    expect(canAsk('   ', false)).toBe(false);
    expect(canAsk('what dropped?', true)).toBe(false);
    expect(canAsk('what dropped?', false)).toBe(true);
  });

  it('detects deny/rate sentences for the preview pane', () => {
    expect(looksLikeDraft('deny dns malware.example')).toBe(true);
    expect(looksLikeDraft('why is DNS failing?')).toBe(false);
  });
});
