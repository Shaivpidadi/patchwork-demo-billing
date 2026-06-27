'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
//
// Uses lodash.set with a user-controlled path — the reachable sink for
// GHSA-p6mc-m468-83gw / CVE-2020-8203 (prototype pollution). There is NO
// patched release of lodash.set (every version 3.7.0..4.3.2 is affected and
// fixedVersion is null), so a version bump cannot fix this. Instead we guard
// the sink in first-party code: any update whose path resolves to a
// prototype-polluting key (__proto__, prototype, constructor) is rejected
// before it ever reaches set().
const set = require('lodash.set');

// Keys that can be abused to walk into and mutate Object.prototype.
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

// Normalize a lodash path (string like 'a.b[0].c' or an array of keys) into
// its individual segments so each can be checked.
function pathSegments(path) {
  if (Array.isArray(path)) {
    return path.map((segment) => String(segment));
  }
  return String(path)
    // collapse bracket access ([0], ['x'], ["x"]) into dot access
    .replace(/\[(['"]?)([^\]]*)\1\]/g, '.$2')
    .split('.')
    .filter((segment) => segment.length > 0);
}

// Throw if any segment of the path targets the object prototype chain.
function assertSafePath(path) {
  for (const segment of pathSegments(path)) {
    if (FORBIDDEN_KEYS.has(segment)) {
      throw new Error(
        `Refusing to apply update: prototype-polluting path segment "${segment}"`
      );
    }
  }
}

function applyUpdates(profile, updates) {
  const target = profile || {};
  for (const { path, value } of updates) {
    // Guard the vulnerable lodash.set sink against prototype pollution.
    assertSafePath(path);
    set(target, path, value);
  }
  return target;
}

module.exports = { applyUpdates, assertSafePath };
