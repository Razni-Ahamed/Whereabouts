import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isIpLiteral } from './host.ts';

test('addresses are not host names', () => {
  for (const ip of ['1.2.3.4', '::1', '2001:db8::1', '[::1]', '::ffff:1.2.3.4', '1.2.3.4:443']) {
    assert.equal(isIpLiteral(ip), true, ip);
  }
});

test('host names are', () => {
  for (const name of ['a8f3kq.example', 'xn--bcher-kva.example', 'example.com', '1.2.3.example']) {
    assert.equal(isIpLiteral(name), false, name);
  }
});
