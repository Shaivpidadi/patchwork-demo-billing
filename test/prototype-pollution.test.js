'use strict';
// Reproduction for GHSA-p6mc-m468-83gw (CVE-2020-8203): prototype pollution
// through the reachable sink applyUpdates() -> lodash.set(target, userPath, value).
// lodash.set has NO patched release, so this must be fixed at the code level by
// rejecting prototype-polluting path segments before the deep-set runs.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

function cleanProto() {
  delete Object.prototype.polluted;
  delete Object.prototype.polluted2;
  delete Object.prototype.polluted3;
}

test('rejects __proto__ in a string path and does not pollute Object.prototype', () => {
  cleanProto();
  assert.equal({}.polluted, undefined);
  assert.throws(
    () => applyUpdates({}, [{ path: '__proto__.polluted', value: 'yes' }]),
    /prototype|proto|pollut/i,
  );
  assert.equal({}.polluted, undefined, 'Object.prototype must not be polluted');
  cleanProto();
});

test('rejects constructor.prototype path and does not pollute Object.prototype', () => {
  cleanProto();
  assert.throws(
    () => applyUpdates({}, [{ path: 'constructor.prototype.polluted2', value: 'yes' }]),
    /prototype|proto|pollut/i,
  );
  assert.equal({}.polluted2, undefined, 'Object.prototype must not be polluted');
  cleanProto();
});

test('rejects __proto__ in an array path and does not pollute Object.prototype', () => {
  cleanProto();
  assert.throws(
    () => applyUpdates({}, [{ path: ['x', '__proto__', 'polluted3'], value: 'yes' }]),
    /prototype|proto|pollut/i,
  );
  assert.equal({}.polluted3, undefined, 'Object.prototype must not be polluted');
  cleanProto();
});

test('still applies legitimate nested updates', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
