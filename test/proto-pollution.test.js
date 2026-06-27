'use strict';
// Security regression test for GHSA-p6mc-m468-83gw / CVE-2020-8203
// (Prototype Pollution in lodash.set). There is NO patched release of
// lodash.set, so this is enforced by a code-level guard in src/merge.js.
//
// Before the fix: applyUpdates() forwards an attacker-controlled path straight
// into lodash.set, which walks into __proto__/constructor.prototype and mutates
// Object.prototype -> these assertions FAIL.
// After the fix: the polluting path is rejected (throws) and Object.prototype
// stays clean -> these assertions PASS.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

const POLLUTING_PATHS = [
  '__proto__.polluted',
  ['__proto__', 'polluted'],
  'constructor.prototype.polluted',
  ['constructor', 'prototype', 'polluted'],
];

for (const path of POLLUTING_PATHS) {
  test(`rejects prototype-polluting path: ${JSON.stringify(path)}`, () => {
    assert.throws(
      () => applyUpdates({}, [{ path, value: 'pwned' }]),
      /prototype-polluting|Refusing/i,
      'applyUpdates must refuse to set a prototype-polluting path'
    );
    // No object anywhere in the process may have been polluted.
    assert.equal({}.polluted, undefined, 'Object.prototype was polluted!');
    assert.equal(({}).polluted, undefined, 'Object.prototype was polluted!');
  });
}

test('still applies legitimate nested updates after the guard', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
