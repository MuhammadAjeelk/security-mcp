import { describe, expect, it } from 'vitest';
import { evaluateMatcher } from '../core/templates/matchers.js';

const inputBase = {
  status: 200,
  headers: { 'content-type': 'text/html', server: 'nginx/1.18' },
  body: 'Hello WORLD — debug=true',
};

describe('evaluateMatcher', () => {
  it('status matcher', () => {
    expect(evaluateMatcher({ type: 'status', status: [200, 301] }, inputBase).matched).toBe(true);
    expect(evaluateMatcher({ type: 'status', status: [404] }, inputBase).matched).toBe(false);
  });

  it('word matcher (case-insensitive default, OR condition)', () => {
    expect(
      evaluateMatcher({ type: 'word', words: ['hello', 'absent'] }, inputBase).matched,
    ).toBe(true);
    expect(
      evaluateMatcher({ type: 'word', words: ['absent'] }, inputBase).matched,
    ).toBe(false);
  });

  it('word matcher AND condition', () => {
    expect(
      evaluateMatcher(
        { type: 'word', words: ['hello', 'world'], condition: 'and' },
        inputBase,
      ).matched,
    ).toBe(true);
    expect(
      evaluateMatcher(
        { type: 'word', words: ['hello', 'absent'], condition: 'and' },
        inputBase,
      ).matched,
    ).toBe(false);
  });

  it('regex matcher', () => {
    expect(
      evaluateMatcher({ type: 'regex', regex: ['debug\\s*=\\s*true'] }, inputBase).matched,
    ).toBe(true);
  });

  it('header matcher — presence only', () => {
    expect(
      evaluateMatcher({ type: 'header', header: 'server' }, inputBase).matched,
    ).toBe(true);
    expect(
      evaluateMatcher({ type: 'header', header: 'x-not-present' }, inputBase).matched,
    ).toBe(false);
  });

  it('header matcher — value contains', () => {
    expect(
      evaluateMatcher(
        { type: 'header', header: 'server', words: ['nginx'] },
        inputBase,
      ).matched,
    ).toBe(true);
    expect(
      evaluateMatcher(
        { type: 'header', header: 'server', words: ['apache'] },
        inputBase,
      ).matched,
    ).toBe(false);
  });

  it('negative inverts the result', () => {
    expect(
      evaluateMatcher({ type: 'header', header: 'x-not-present', negative: true }, inputBase)
        .matched,
    ).toBe(true);
  });
});
