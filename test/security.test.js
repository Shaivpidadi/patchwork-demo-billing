'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

test('SECURITY: blocks prototype pollution via user-controlled path', () => {
  assert.throws(
    () => applyUpdates({}, [{ path: '__proto__.polluted', value: 'pwned' }]),
    /prototype-polluting/,
  );
  assert.equal({}.polluted, undefined, 'Object.prototype stays clean');
});

test('SECURITY: still allows legitimate nested paths', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});
