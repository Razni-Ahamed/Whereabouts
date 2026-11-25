import { test } from 'node:test';
import assert from 'node:assert/strict';
import { activeHoursBars, daysLeft } from './profile.ts';

test('active hours scale to 0 to 8, the busiest hour being 8', () => {
  const shares = Array.from({ length: 24 }, () => 0);
  shares[9] = 0.4;
  shares[10] = 0.2;
  shares[3] = 0.001;
  const bars = activeHoursBars(shares);
  assert.equal(bars.length, 24);
  assert.equal(bars[9], 8);
  assert.equal(bars[10], 4);
  assert.equal(bars[3], 1, 'an hour that was active never shows as empty');
  assert.equal(bars[0], 0);
});

test('a program that was never active has no bars', () => {
  assert.deepEqual(activeHoursBars(Array.from({ length: 24 }, () => 0)), Array.from({ length: 24 }, () => 0));
});

test('odd input never gives NaN or out-of-range bars', () => {
  const bars = activeHoursBars([Number.NaN, -1, Number.POSITIVE_INFINITY, 0.5]);
  assert.ok(bars.every((b) => Number.isInteger(b) && b >= 0 && b <= 8));
});

test('days left rounds up and never goes below zero', () => {
  const now = 1_000_000;
  assert.equal(daysLeft(now + 6 * 86_400 + 1, now), 7);
  assert.equal(daysLeft(now + 86_400, now), 1);
  assert.equal(daysLeft(now - 5, now), 0);
});
