'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
// Uses lodash.set with a user-controlled path — the reachable sink for
// GHSA-p6mc-m468-83gw (prototype pollution). There is NO patched release of
// lodash.set, so a version bump cannot fix this; only a code-level guard can.
const set = require('lodash.set');

function applyUpdates(profile, updates) {
  const target = profile || {};
  for (const { path, value } of updates) {
    set(target, path, value);
  }
  return target;
}

module.exports = { applyUpdates };
