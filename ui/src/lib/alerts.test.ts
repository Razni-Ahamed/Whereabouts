import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dismissEach } from './alerts.ts';

test('dismisses every alert, one at a time, and counts what failed', async () => {
  const seen: number[] = [];
  const result = await dismissEach([1, 2, 3], async (id) => {
    seen.push(id);
    return id === 2 ? { ok: false, message: 'still learning' } : { ok: true };
  });
  assert.deepEqual(seen, [1, 2, 3]);
  assert.deepEqual(result, { done: 2, failed: 1, firstError: 'still learning' });
});

test('nothing to dismiss does nothing', async () => {
  const result = await dismissEach([], async () => {
    throw new Error('not called');
  });
  assert.deepEqual(result, { done: 0, failed: 0, firstError: null });
});
