import { test } from 'node:test';
import assert from 'node:assert/strict';
import { COUNTRY_CENTRES, countryCentre, isLand, landMask } from './geo.ts';

function near(actual: [number, number] | null, expected: [number, number], within: number) {
  assert.ok(actual, 'expected a centre');
  assert.ok(Math.abs(actual[0] - expected[0]) <= within, `lat ${actual[0]} not within ${within} of ${expected[0]}`);
  assert.ok(Math.abs(actual[1] - expected[1]) <= within, `lon ${actual[1]} not within ${within} of ${expected[1]}`);
}

test('centres are valid', () => {
  const entries = Object.entries(COUNTRY_CENTRES);
  assert.ok(entries.length >= 240, `only ${entries.length} centres`);
  for (const [code, [lat, lon]] of entries) {
    assert.match(code, /^[A-Z]{2}$/);
    assert.ok(lat >= -90 && lat <= 90, `${code} lat ${lat}`);
    assert.ok(lon >= -180 && lon <= 180, `${code} lon ${lon}`);
  }
});

test('lookup', () => {
  near(countryCentre('US'), [39, -98], 3);
  near(countryCentre('lk'), [7.9, 80.8], 1);
  assert.equal(countryCentre(null), null);
  assert.equal(countryCentre('ZZ'), null);
  assert.equal(countryCentre(''), null);
});

test('big countries sit on land', () => {
  const mask = landMask();
  const codes = 'US CA MX BR AR GB FR DE ES IT PL RU CN IN AU ZA EG NG KE SA IR JP ID TR KZ'.split(' ');
  for (const code of codes) {
    const centre = countryCentre(code);
    assert.ok(centre, code);
    assert.ok(isLand(mask, centre[0], centre[1]), `${code} at ${centre} is not on land`);
  }
});

test('oceans are water', () => {
  const mask = landMask();
  assert.equal(isLand(mask, 0, -140), false);
  assert.equal(isLand(mask, -30, -20), false);
  assert.equal(isLand(mask, -20, 75), false);
});
