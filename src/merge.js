'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
// Uses lodash.set with a user-controlled path — the reachable sink for
// GHSA-p6mc-m468-83gw / CVE-2020-8203 (prototype pollution). There is NO
// patched release of lodash.set (every version up to and including the latest
// 4.3.2 is affected), so a version bump cannot fix this. The only viable fix is
// a code-level guard that rejects prototype-polluting path segments before the
// value ever reaches lodash.set.
const set = require('lodash.set');

// Property names that let an attacker walk up to and mutate Object.prototype.
const POLLUTERS = new Set(['__proto__', 'prototype', 'constructor']);

// Normalize a lodash-style path (string like "a.b[0].c" or an array) into its
// individual property segments so each one can be vetted.
function toSegments(path) {
  if (Array.isArray(path)) {
    return path.map((segment) => String(segment));
  }
  return String(path)
    .replace(/\[(\d+)\]/g, '.$1') // a[0] -> a.0
    .split(/[.[\]'"]+/)
    .filter((segment) => segment.length > 0);
}

// Reject any path that attempts to traverse a prototype-polluting key.
function assertSafePath(path) {
  for (const segment of toSegments(path)) {
    if (POLLUTERS.has(segment)) {
      throw new Error(
        `Refusing to set a prototype-polluting path: "${segment}" is not an allowed key`,
      );
    }
  }
}

function applyUpdates(profile, updates) {
  const target = profile || {};
  for (const { path, value } of updates) {
    assertSafePath(path);
    set(target, path, value);
  }
  return target;
}

module.exports = { applyUpdates, assertSafePath };
