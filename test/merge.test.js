'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { applyUpdates } = require('../src/merge');

test('applies normal nested updates', () => {
  const out = applyUpdates({}, [{ path: 'billing.plan', value: 'pro' }]);
  assert.equal(out.billing.plan, 'pro');
});

test('overwrites existing fields', () => {
  const out = applyUpdates({ billing: { plan: 'free' } }, [{ path: 'billing.plan', value: 'enterprise' }]);
  assert.equal(out.billing.plan, 'enterprise');
});
