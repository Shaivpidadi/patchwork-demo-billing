'use strict';
// Reproduction + regression test for GHSA-p6mc-m468-83gw (CVE-2020-8203).
// Prototype pollution in lodash.set, reached through the user-controlled
// `path` argument of applyUpdates() in src/merge.js.
//
// There is NO patched release of lodash.set, so this is fixed in first-party
// code (a guard that rejects prototype-polluting path segments).
//
// BEFORE the fix: applyUpdates() does not throw and Object.prototype is
//   polluted -> this test FAILS (proving the vulnerability is reachable).
// AFTER the fix: applyUpdates() throws on the malicious path and the
//   prototype stays clean -> this test PASSES.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

test('rejects prototype-polluting user-supplied paths (GHSA-p6mc-m468-83gw)', () => {
  delete Object.prototype.polluted;

  assert.throws(
    () => applyUpdates({}, [{ path: '__proto__.polluted', value: 'pwned' }]),
    /prototype-polluting|Refusing/i,
    'applyUpdates must reject a path that targets the object prototype'
  );

  // Regardless of the throw, the global prototype must remain untouched.
  assert.equal(
    ({}).polluted,
    undefined,
    'Object.prototype was polluted via lodash.set'
  );

  delete Object.prototype.polluted;
});

test('blocks constructor.prototype pollution variant', () => {
  delete Object.prototype.polluted2;

  assert.throws(
    () => applyUpdates({}, [{ path: 'constructor.prototype.polluted2', value: 'pwned' }]),
    /prototype-polluting|Refusing/i
  );

  assert.equal(({}).polluted2, undefined);
  delete Object.prototype.polluted2;
});

test('still applies legitimate nested updates', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
