import { test } from 'node:test';
import assert from 'node:assert/strict';
import { alertTitle, moreReasonsText, reasonText } from './reasons.ts';
import type { AlertView, ReasonView } from './types.ts';

const reason = (r: Partial<ReasonView> & { signal: string }): ReasonView => ({
  value: null,
  observed: null,
  usual: null,
  count: null,
  ...r,
});

test('describes an upload spike with both sizes', () => {
  assert.equal(
    reasonText(reason({ signal: 'upload_spike', observed: 356_515_840, usual: 5_242_880 })),
    'Uploaded 340 MB in an hour. Usually about 5.0 MB.',
  );
});

test('falls back without numbers, never printing undefined or NaN', () => {
  const text = reasonText(reason({ signal: 'upload_spike', observed: Number.NaN }));
  assert.equal(text, 'Uploaded much more than usual in an hour.');
  assert.doesNotMatch(text, /undefined|NaN|null/);
});

test('names the country', () => {
  assert.equal(reasonText(reason({ signal: 'new_country', value: 'RU' })), 'First connection to Russia');
});

test('describes the other signals', () => {
  assert.equal(reasonText(reason({ signal: 'new_site', value: 'evil.example' })), 'New site: evil.example');
  assert.equal(reasonText(reason({ signal: 'new_company', value: 'Selectel' })), 'First time using Selectel');
  assert.equal(
    reasonText(reason({ signal: 'ratio_flip', observed: 5_242_880 })),
    'Sent more than it received this hour (5.0 MB sent). It usually mostly downloads.',
  );
  assert.equal(
    reasonText(reason({ signal: 'beaconing', value: 'c2.example', observed: 60.4, count: 12 })),
    'Connected to c2.example every 60 seconds, 12 times.',
  );
  assert.equal(reasonText(reason({ signal: 'unusual_time', value: '03' })), 'Active at an hour it rarely is (03:00).');
  assert.equal(
    reasonText(reason({ signal: 'random_name', value: 'x7qk2.top' })),
    'Used a random-looking name: x7qk2.top',
  );
  assert.equal(
    reasonText(reason({ signal: 'binary_changed' })),
    'Its program file changed and is no longer signed by the same publisher, and it reached somewhere new.',
  );
});

test('counts the reasons an alert left out', () => {
  assert.equal(moreReasonsText(undefined), null);
  assert.equal(moreReasonsText(0), null);
  assert.equal(moreReasonsText(1), 'and 1 more');
  assert.equal(moreReasonsText(4_976), 'and 4,976 more');
});

test('falls back for an unknown signal', () => {
  assert.equal(reasonText(reason({ signal: 'x' })), 'Unusual behaviour');
});

test('a behaviour alert is titled with the app', () => {
  const base: AlertView = {
    id: 1,
    created_secs: 0,
    kind: 'behaviour',
    severity: 'high',
    app: 'chat.exe',
    path: null,
    target: null,
    detail: null,
    dismissed: false,
    can_allow: true,
  };
  assert.equal(alertTitle(base), 'chat is behaving differently');
  assert.equal(alertTitle({ ...base, app: null }), 'An app is behaving differently');
});

test('says when a program may be posing as another', () => {
  const known = String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`;
  assert.equal(
    reasonText(reason({ signal: 'impostor', value: known })),
    `Same name as ${known}, but not signed by the same publisher. It may be pretending to be that program.`,
  );
  assert.equal(
    reasonText(reason({ signal: 'impostor', value: null })),
    'Same name as a program you already use, but not signed by the same publisher.',
  );
  assert.equal(
    reasonText(reason({ signal: 'impostor_unchecked', value: known })),
    `Same name as ${known}, but its signature couldn't be checked. It may be pretending to be that program.`,
  );
  assert.equal(
    reasonText(reason({ signal: 'impostor_unchecked', value: null })),
    "Same name as a program you already use, but its signature couldn't be checked.",
  );
});
