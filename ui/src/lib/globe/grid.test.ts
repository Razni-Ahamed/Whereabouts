import { test } from 'node:test';
import assert from 'node:assert/strict';
import { regrid, sameCountries } from './grid.ts';

// A 3 × 2 grid: row 0 = 1 2 3, row 1 = 4 5 6.
const grid = () => new Float32Array([1, 2, 3, 4, 5, 6]);

test('regrid keeps every cell when the size is unchanged', () => {
  assert.deepEqual([...regrid(grid(), 3, 2, 3, 2, () => 9)], [1, 2, 3, 4, 5, 6]);
});

test('regrid keeps cells at their row and column when growing', () => {
  const out = regrid(grid(), 3, 2, 4, 3, () => 0);
  assert.deepEqual([...out], [1, 2, 3, 0, 4, 5, 6, 0, 0, 0, 0, 0]);
});

test('regrid drops cells outside when shrinking', () => {
  assert.deepEqual([...regrid(grid(), 3, 2, 2, 1, () => 0)], [1, 2]);
});

test('regrid keeps the array type', () => {
  const out = regrid(new Uint8Array([7, 8]), 2, 1, 3, 1, () => 1);
  assert.ok(out instanceof Uint8Array);
  assert.deepEqual([...out], [7, 8, 1]);
});

test('sameCountries', () => {
  const a = new Map([['US', false], ['DE', true]]);
  assert.equal(sameCountries(a, new Map([['DE', true], ['US', false]])), true);
  assert.equal(sameCountries(a, new Map([['US', false], ['DE', false]])), false);
  assert.equal(sameCountries(a, new Map([['US', false]])), false);
  assert.equal(sameCountries(new Map(), new Map()), true);
});
