import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_PINGS, PingTracker, activeCountries, type FlowLike } from './pings.ts';

const isWarn = (owner: string | null) => owner?.includes('analytics') ?? false;
const flow = (app: string, remote: string, country: string | null, owner: string | null = null): FlowLike => ({
  app,
  remote,
  country,
  owner,
});
const base = [flow('chrome.exe', '1.1.1.1:443', 'US'), flow('Spotify.exe', '2.2.2.2:443', 'SE')];

test('first update sets the baseline', () => {
  const tracker = new PingTracker(isWarn);
  assert.deepEqual(tracker.update(base), []);
});

test('new flow pings its country', () => {
  const tracker = new PingTracker(isWarn);
  tracker.update(base);
  assert.deepEqual(tracker.update([...base, flow('updater.exe', '3.3.3.3:443', 'DE')]), [
    { country: 'DE', warn: false },
  ]);
});

test('tracker pings amber', () => {
  const tracker = new PingTracker(isWarn);
  tracker.update(base);
  const pings = tracker.update([...base, flow('chrome.exe', '4.4.4.4:443', 'US', 'Adobe · analytics')]);
  assert.deepEqual(pings, [{ country: 'US', warn: true }]);
});

test('skips unknown countries', () => {
  const tracker = new PingTracker(isWarn);
  tracker.update(base);
  const pings = tracker.update([...base, flow('svchost.exe', '192.168.1.1:53', null), flow('x.exe', '5.5.5.5:443', 'ZZ')]);
  assert.deepEqual(pings, []);
});

test('caps pings per update', () => {
  const tracker = new PingTracker(isWarn);
  tracker.update(base);
  const many = Array.from({ length: 50 }, (_, i) => flow('chrome.exe', `9.9.9.${i}:443`, 'US'));
  assert.equal(tracker.update([...base, ...many]).length, MAX_PINGS);
});

test('duplicates ping once', () => {
  const tracker = new PingTracker(isWarn);
  tracker.update(base);
  const twice = flow('Code.exe', '13.107.6.175:443', 'US');
  assert.equal(tracker.update([...base, twice, { ...twice }]).length, 1);
});

test('empty update resets the baseline', () => {
  const tracker = new PingTracker(isWarn);
  tracker.update(base);
  assert.deepEqual(tracker.update([]), []);
  const ten = Array.from({ length: 10 }, (_, i) => flow('chrome.exe', `8.8.8.${i}:443`, 'US'));
  assert.deepEqual(tracker.update(ten), []);
});

test('a connection that closes and reopens pings again', () => {
  const tracker = new PingTracker(isWarn);
  const extra = flow('updater.exe', '3.3.3.3:443', 'DE');
  tracker.update(base);
  tracker.update([...base, extra]);
  tracker.update(base);
  assert.equal(tracker.update([...base, extra]).length, 1);
});

test('activeCountries', () => {
  const flows = [
    flow('chrome.exe', '1.1.1.1:443', 'US'),
    flow('chrome.exe', '4.4.4.4:443', 'us', 'Adobe · analytics'),
    flow('svchost.exe', '192.168.1.1:53', null),
    flow('x.exe', '5.5.5.5:443', 'ZZ'),
  ];
  assert.deepEqual(activeCountries(flows, isWarn), new Map([['US', true]]));
});
