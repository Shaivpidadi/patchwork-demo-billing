'use strict';
// Regression test for GHSA-p6mc-m468-83gw (CVE-2020-8203): prototype pollution
// via lodash.set when a user-controlled path reaches the sink in applyUpdates().
// There is NO patched release of lodash.set, so this is mitigated with a
// code-level guard. BEFORE the fix: the malicious update pollutes Object.prototype
// and nothing is thrown -> these tests FAIL. AFTER the fix: the polluting path is
// rejected and the prototype is never touched -> these tests PASS.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

test('rejects __proto__ path and does not pollute Object.prototype', () => {
  delete Object.prototype.polluted;
  assert.equal({}.polluted, undefined, 'precondition: prototype is clean');

  assert.throws(
    () => applyUpdates({}, [{ path: '__proto__.polluted', value: true }]),
    /prototype-polluting/i,
    'a polluting path must be refused',
  );

  // The global prototype must remain untouched regardless.
  assert.equal({}.polluted, undefined, 'Object.prototype must NOT be polluted');
  delete Object.prototype.polluted;
});

test('rejects constructor.prototype path', () => {
  delete Object.prototype.hacked;
  assert.throws(
    () => applyUpdates({}, [{ path: 'constructor.prototype.hacked', value: true }]),
    /prototype-polluting/i,
  );
  assert.equal({}.hacked, undefined, 'Object.prototype must NOT be polluted');
  delete Object.prototype.hacked;
});

test('rejects polluting segment supplied as an array path', () => {
  delete Object.prototype.viaArray;
  assert.throws(
    () => applyUpdates({}, [{ path: ['__proto__', 'viaArray'], value: true }]),
    /prototype-polluting/i,
  );
  assert.equal({}.viaArray, undefined);
  delete Object.prototype.viaArray;
});

test('still applies legitimate nested updates', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
