import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_PINGS, PingTracker, SEEN_FOR_S, WARM_UP_S, activeCountries, type FlowLike } from './pings.ts';

const isWarn = (owner: string | null) => owner?.includes('analytics') ?? false;
const flow = (
  app: string,
  remote: string,
  country: string | null,
  owner: string | null = null,
  active = true,
): FlowLike => ({ app, remote, country, owner, active });
const base = [flow('chrome.exe', '1.1.1.1:443', 'US'), flow('Spotify.exe', '2.2.2.2:443', 'SE')];

/** A tracker plus a clock: the service has been up long past its warm-up. */
function setup(uptime = 3600) {
  const tracker = new PingTracker(isWarn);
  let now = 1_000_000;
  let up = uptime;
  return {
    /** One refresh, `dt` seconds after the previous one. */
    update(flows: FlowLike[], dt = 2) {
      now += dt;
      up += dt;
      return tracker.update(flows, up, now);
    },
    /** The service restarted: its uptime starts again from `to`. */
    restart(to = 0) {
      up = to;
    },
  };
}

test('first update sets the baseline', () => {
  const t = setup();
  assert.deepEqual(t.update(base), []);
});

test('new flow pings its country', () => {
  const t = setup();
  t.update(base);
  assert.deepEqual(t.update([...base, flow('updater.exe', '3.3.3.3:443', 'DE')]), [{ country: 'DE', warn: false }]);
});

test('tracker pings amber', () => {
  const t = setup();
  t.update(base);
  const pings = t.update([...base, flow('chrome.exe', '4.4.4.4:443', 'US', 'Adobe · analytics')]);
  assert.deepEqual(pings, [{ country: 'US', warn: true }]);
});

test('skips unknown countries', () => {
  const t = setup();
  t.update(base);
  assert.deepEqual(t.update([...base, flow('svchost.exe', '192.168.1.1:53', null), flow('x.exe', '5.5.5.5:443', 'ZZ')]), []);
});

test('caps pings per update', () => {
  const t = setup();
  t.update(base);
  const many = Array.from({ length: 50 }, (_, i) => flow('chrome.exe', `9.9.9.${i}:443`, 'US'));
  assert.equal(t.update([...base, ...many]).length, MAX_PINGS);
});

test('duplicates ping once', () => {
  const t = setup();
  t.update(base);
  const twice = flow('Code.exe', '13.107.6.175:443', 'US');
  assert.equal(t.update([...base, twice, { ...twice }]).length, 1);
});

test('empty update resets the baseline', () => {
  const t = setup();
  t.update(base);
  assert.deepEqual(t.update([]), []);
  const ten = Array.from({ length: 10 }, (_, i) => flow('chrome.exe', `8.8.8.${i}:443`, 'US'));
  assert.deepEqual(t.update(ten), []);
});

test('closed flows never ping', () => {
  const t = setup();
  t.update(base);
  assert.deepEqual(t.update([...base, flow('Spotify.exe', '7.7.7.7:443', 'SE', null, false)]), []);
});

test('a flow that drops out of the list and comes back soon does not ping again', () => {
  const t = setup();
  const big = flow('steam.exe', '6.6.6.6:443', 'SG');
  t.update([...base, big]);
  t.update(base);
  t.update(base, SEEN_FOR_S - 30);
  assert.deepEqual(t.update([...base, big]), []);
});

test('a flow not seen for longer than SEEN_FOR_S pings again', () => {
  const t = setup();
  const extra = flow('updater.exe', '3.3.3.3:443', 'DE');
  t.update([...base, extra]);
  t.update(base, SEEN_FOR_S + 10);
  assert.equal(t.update([...base, extra]).length, 1);
});

test('no pings while the service warms up after a restart', () => {
  const t = setup();
  t.update(base);
  t.restart(0);
  // The service rebuilds its table bit by bit: connections open all along reappear.
  assert.deepEqual(t.update([...base, flow('ms-teams.exe', '52.1.1.1:443', 'IE')]), []);
  assert.deepEqual(t.update([...base, flow('ms-teams.exe', '52.1.1.1:443', 'IE'), flow('zoom.exe', '149.1.1.1:443', 'SG')]), []);
  // After the warm-up, a really new connection pings again.
  t.update(base, WARM_UP_S);
  assert.equal(t.update([...base, flow('Discord.exe', '162.1.1.1:443', 'US')]).length, 1);
});

test('activeCountries counts only open connections', () => {
  const flows = [
    flow('chrome.exe', '1.1.1.1:443', 'US'),
    flow('chrome.exe', '4.4.4.4:443', 'us', 'Adobe · analytics'),
    flow('Spotify.exe', '2.2.2.2:443', 'SE', null, false),
    flow('svchost.exe', '192.168.1.1:53', null),
    flow('x.exe', '5.5.5.5:443', 'ZZ'),
  ];
  assert.deepEqual(activeCountries(flows, isWarn), new Map([['US', true]]));
});
