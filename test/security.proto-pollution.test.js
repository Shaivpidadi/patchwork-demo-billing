'use strict';
// Reproduction for GHSA-p6mc-m468-83gw / CVE-2020-8203 (prototype pollution).
// applyUpdates() feeds a user-controlled `path` straight into lodash.set, the
// vulnerable sink. lodash.set has NO patched release (fixedVersion === null),
// so this must be fixed in first-party code with a guard.
//
// BEFORE the fix: applyUpdates does NOT throw and Object.prototype gets polluted
//                 -> these assertions fail.
// AFTER the fix:  applyUpdates rejects the polluting path and the prototype is
//                 left clean -> assertions pass.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

const POLLUTING_PATHS = [
  '__proto__.polluted',
  ['__proto__', 'polluted'],
  'constructor.prototype.polluted',
  'a[constructor][prototype][polluted]',
];

test('rejects prototype-polluting paths and never pollutes Object.prototype', () => {
  for (const path of POLLUTING_PATHS) {
    assert.throws(
      () => applyUpdates({}, [{ path, value: 'PWNED' }]),
      /pollut/i,
      `expected applyUpdates to reject polluting path: ${JSON.stringify(path)}`,
    );
    const leaked = ({}).polluted;
    if (leaked !== undefined) delete Object.prototype.polluted; // cleanup if vulnerable
    assert.equal(leaked, undefined, `Object.prototype was polluted via ${JSON.stringify(path)}`);
  }
});

test('still applies legitimate nested updates', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
