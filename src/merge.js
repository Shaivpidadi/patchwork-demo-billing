'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
//
// Uses lodash.set with a user-controlled path — the reachable sink for
// GHSA-p6mc-m468-83gw / CVE-2020-8203 (prototype pollution). There is NO
// patched release of lodash.set (affected at every version up to and including
// the latest, 4.3.2), so a version bump CANNOT fix this. The mitigation below
// is a code-level guard that rejects prototype-polluting path segments before
// they ever reach lodash.set.
const set = require('lodash.set');

// Path segments that, if writable, let an attacker reach Object.prototype.
const POLLUTERS = new Set(['__proto__', 'constructor', 'prototype']);

// Normalize a lodash path (string with dot/bracket notation, or an array of
// keys) into a flat list of string segments so each can be vetted.
function pathSegments(path) {
  if (Array.isArray(path)) {
    return path.map((segment) => String(segment));
  }
  return String(path)
    // Convert bracket accessors to dot segments: a[0] -> a.0, a['x'] -> a.x,
    // __proto__[polluted] -> __proto__.polluted.
    .replace(/\[(['"]?)([^\]]*)\1\]/g, '.$2')
    .split('.')
    .filter((segment) => segment.length > 0);
}

function isPollutingPath(path) {
  return pathSegments(path).some((segment) => POLLUTERS.has(segment));
}

function applyUpdates(profile, updates) {
  const target = profile || {};
  for (const { path, value } of updates) {
    if (isPollutingPath(path)) {
      throw new Error(
        'Refusing to set a prototype-polluting path: ' + String(path)
      );
    }
    set(target, path, value);
  }
  return target;
}

module.exports = { applyUpdates, isPollutingPath };
