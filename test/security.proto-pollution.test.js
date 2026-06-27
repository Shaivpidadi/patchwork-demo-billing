'use strict';
// Reproduction for GHSA-p6mc-m468-83gw (CVE-2020-8203): Prototype Pollution.
// applyUpdates() passes a user-controlled `path` into lodash.set, the reachable
// sink. A malicious path like `__proto__.polluted` or `constructor.prototype.x`
// mutates Object.prototype. lodash.set has NO patched release, so this can only
// be fixed in first-party code. This test FAILS before the code-level guard and
// PASSES after.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

test('rejects __proto__ path and does not pollute Object.prototype', () => {
  assert.equal({}.polluted, undefined, 'precondition: prototype clean');
  assert.throws(
    () => applyUpdates({}, [{ path: '__proto__.polluted', value: true }]),
    /prototype-polluting|pollut/i,
  );
  assert.equal({}.polluted, undefined, 'Object.prototype must NOT be polluted');
});

test('rejects constructor.prototype path and does not pollute Object.prototype', () => {
  assert.equal({}.polluted2, undefined, 'precondition: prototype clean');
  assert.throws(
    () => applyUpdates({}, [{ path: 'constructor.prototype.polluted2', value: true }]),
    /prototype-polluting|pollut/i,
  );
  assert.equal({}.polluted2, undefined, 'Object.prototype must NOT be polluted');
});

test('still applies safe nested updates', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
