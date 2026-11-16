import { describe, expect, it } from 'vitest';
import { exportProgress, importProgress, load, recordAttempt, recordResult, resetProgress } from '../src/ui/store';

// Runs without localStorage (node), so the store uses its in-memory fallback,
// the same path a browser takes when storage is disabled.

function answerOne(): void {
  recordAttempt('m01', 'seed-a', 'q1', true);
  recordResult({ concept: 'm01', qid: 'q1', seed: 'seed-a', source: 'learn', correct: true, confidence: 'sure' });
}

function expectEmpty(): void {
  const s = load();
  expect(s.records).toEqual([]);
  expect(s.attempts).toEqual({});
  expect(s.explain).toEqual({});
  expect(s.findOut).toEqual({});
}

describe('progress store', () => {
  it('reset clears progress made in the same session', () => {
    answerOne();
    expect(load().records).toHaveLength(1);
    resetProgress();
    expectEmpty();
  });

  it('a second reset in the same session also clears', () => {
    answerOne();
    resetProgress();
    answerOne();
    resetProgress();
    expectEmpty();
  });

  it('importing an export that lacks some fields does not revive old progress', () => {
    answerOne();
    const partial = JSON.stringify({ attempts: {} });
    expect(importProgress(partial)).toBe(true);
    expectEmpty();
  });

  it('export then import round-trips', () => {
    answerOne();
    const saved = exportProgress();
    resetProgress();
    expect(importProgress(saved)).toBe(true);
    expect(load().records).toHaveLength(1);
    expect(load().attempts.m01['seed-a'].q1.correct).toBe(true);
    resetProgress();
  });
});
