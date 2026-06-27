'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
//
// `lodash.set` is the reachable sink for GHSA-p6mc-m468-83gw / CVE-2020-8203
// (prototype pollution): a user-controlled `path` can traverse `__proto__`,
// `constructor`, or `prototype` and mutate the global Object prototype.
//
// There is NO patched release of lodash.set (location.fixedVersion === null),
// so a version bump cannot fix this. Instead we guard the sink at the call
// site by rejecting prototype-polluting path segments before delegating.
const set = require('lodash.set');

// Segments that can walk into an object's prototype chain.
const POLLUTING_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);

// Normalize a lodash path (string or array) into discrete segments. Mirrors the
// subset of lodash path syntax this app uses: dot paths and bracketed indices.
function toSegments(path) {
  if (Array.isArray(path)) return path.map(String);
  return String(path)
    .replace(/\[(\d+)\]/g, '.$1')
    .replace(/^\./, '')
    .split('.');
}

// Throw if any segment of `path` would pollute the prototype chain.
function assertSafePath(path) {
  const segments = toSegments(path);
  if (segments.some((segment) => POLLUTING_SEGMENTS.has(segment))) {
    throw new Error(
      `Refusing to set a prototype-polluting path: ${JSON.stringify(path)}`,
    );
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
