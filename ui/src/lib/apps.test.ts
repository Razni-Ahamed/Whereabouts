import { test } from 'node:test';
import assert from 'node:assert/strict';
import { appKey, findApp, folderOf, groupByApp } from './apps.ts';
import type { FlowView } from './types.ts';

function flow(app: string, path: string | null, publisher: string, confirmed: boolean, bytes: number): FlowView {
  return {
    pid: 1,
    app,
    path,
    publisher,
    publisher_confirmed: confirmed,
    protocol: 'TCP',
    domain: null,
    domain_trust: null,
    via: null,
    owner: null,
    country: null,
    remote: '203.0.113.5:443',
    bytes_sent: bytes,
    bytes_received: 0,
    active: true,
  };
}

const REAL = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const FAKE = 'C:\\Users\\me\\AppData\\Local\\Temp\\chrome.exe';

test('a program with a borrowed name gets its own app, with its own publisher', () => {
  const groups = groupByApp([
    flow('chrome.exe', REAL, 'Google LLC', true, 1000),
    flow('chrome.exe', FAKE, 'UNSIGNED', false, 10),
  ]);
  assert.equal(groups.length, 2);
  const [real, fake] = groups;
  assert.equal(real.path, REAL);
  assert.equal(real.publisher, 'Google LLC');
  assert.equal(fake.path, FAKE);
  assert.equal(fake.publisher, 'UNSIGNED');
  assert.equal(fake.publisherConfirmed, false);
  assert.ok(real.sameName && fake.sameName, 'both are marked, so the folder is shown');
});

test('connections of one program are one app, whatever the letter case of its path', () => {
  const groups = groupByApp([
    flow('chrome.exe', REAL, 'Google LLC', true, 5),
    flow('chrome.exe', REAL.toUpperCase(), 'Google LLC', true, 7),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].flows.length, 2);
  assert.equal(groups[0].sent, 12);
  assert.equal(groups[0].sameName, false);
});

test('a program whose path is unknown is never merged into one whose path is known', () => {
  const groups = groupByApp([
    flow('chrome.exe', REAL, 'Google LLC', true, 5),
    flow('chrome.exe', null, '-', false, 1),
  ]);
  assert.equal(groups.length, 2);
  assert.equal(groups[1].path, null);
});

test('an app is found by its key, or by name from places that only know the name', () => {
  const groups = groupByApp([
    flow('chrome.exe', REAL, 'Google LLC', true, 1000),
    flow('chrome.exe', FAKE, 'UNSIGNED', false, 10),
  ]);
  assert.equal(findApp(groups, appKey('chrome.exe', FAKE))?.path, FAKE);
  assert.equal(findApp(groups, 'chrome.exe')?.path, REAL, 'the largest of that name');
  assert.equal(findApp(groups, 'missing.exe'), undefined);
  assert.equal(findApp(groups, null), undefined);
});

test('folders are cut from full paths', () => {
  assert.equal(folderOf(FAKE), 'C:\\Users\\me\\AppData\\Local\\Temp');
  assert.equal(folderOf('chrome.exe'), 'chrome.exe');
});
