'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
// Uses lodash.set with a user-controlled path — the reachable sink for
// GHSA-p6mc-m468-83gw / CVE-2020-8203 (prototype pollution). There is NO
// patched release of lodash.set (fixedVersion === null), so a version bump
// cannot fix this. Instead we guard the sink: any path that would walk into
// the prototype chain is rejected before it ever reaches lodash.set.
const set = require('lodash.set');

// Property identifiers that let a path escape into Object.prototype.
const POLLUTERS = new Set(['__proto__', 'constructor', 'prototype']);

// Normalize a lodash path (string or array) into discrete property segments.
// Handles dot notation, bracket notation, and quoted keys:
//   'a.b'                         -> ['a', 'b']
//   'a[constructor][prototype]'   -> ['a', 'constructor', 'prototype']
//   ['__proto__', 'polluted']     -> ['__proto__', 'polluted']
function pathSegments(path) {
  if (Array.isArray(path)) return path.map((segment) => String(segment));
  return String(path)
    .replace(/\[(['"]?)([^\]]*)\1\]/g, '.$2') // a[b] / a['b'] -> a.b
    .split('.')
    .filter((segment) => segment.length > 0);
}

function assertSafePath(path) {
  for (const segment of pathSegments(path)) {
    if (POLLUTERS.has(segment)) {
      throw new Error(
        `Refusing to apply prototype-polluting path segment: "${segment}"`,
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

module.exports = { applyUpdates };
