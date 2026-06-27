'use strict';
// Reproduction + regression test for GHSA-p6mc-m468-83gw (CVE-2020-8203):
// Prototype Pollution through lodash.set with a user-controlled path.
//
// `applyUpdates(profile, updates)` feeds an attacker-controlled `path` straight
// into lodash.set. lodash.set has NO patched release, so the only fix is a
// code-level guard. These tests assert the SECURE behavior: a polluting path is
// rejected and Object.prototype is never modified.
//
// BEFORE the fix these FAIL (the call silently pollutes Object.prototype).
// AFTER the fix these PASS (the call throws and the prototype stays clean).
const { test, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

afterEach(() => {
  // Defensive cleanup so a regression can't leak across tests.
  delete Object.prototype.polluted;
  delete Object.prototype.polluted2;
  delete Object.prototype.polluted3;
});

test('rejects prototype pollution via __proto__ path', () => {
  assert.throws(
    () => applyUpdates({}, [{ path: '__proto__.polluted', value: true }]),
    /prototype-polluting/i
  );
  assert.notEqual({}.polluted, true, 'Object.prototype must not be polluted');
});

test('rejects prototype pollution via constructor.prototype path', () => {
  assert.throws(
    () => applyUpdates({}, [{ path: 'constructor.prototype.polluted2', value: true }]),
    /prototype-polluting/i
  );
  assert.notEqual({}.polluted2, true, 'Object.prototype must not be polluted');
});

test('rejects prototype pollution via bracket-notation __proto__ path', () => {
  assert.throws(
    () => applyUpdates({}, [{ path: "__proto__[polluted3]", value: true }]),
    /prototype-polluting/i
  );
  assert.notEqual({}.polluted3, true, 'Object.prototype must not be polluted');
});

test('still applies legitimate nested updates', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
