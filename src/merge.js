'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
// Uses lodash.set with a user-controlled path — the reachable sink for
// GHSA-p6mc-m468-83gw / CVE-2020-8203 (prototype pollution). There is NO
// patched release of lodash.set, so a version bump cannot fix this; the
// code-level guard below rejects prototype-polluting path segments
// (__proto__ / constructor / prototype) before the value ever reaches
// lodash.set.
const set = require('lodash.set');

const POLLUTERS = new Set(['__proto__', 'constructor', 'prototype']);

// Normalize a lodash path (a string using dot and/or bracket notation, or an
// array of segments) into an array of individual key segments so each can be
// screened for prototype-polluting identifiers.
function toSegments(path) {
  if (Array.isArray(path)) return path.map(String);
  return String(path)
    // turn bracket access a[b] / a['b'] / a["b"] into dot access a.b
    .replace(/\[(?:'([^']*)'|"([^"]*)"|([^\]]*))\]/g, (_m, s, d, b) => '.' + (s ?? d ?? b))
    .split('.')
    .filter((seg) => seg.length > 0);
}

function assertSafePath(path) {
  if (toSegments(path).some((seg) => POLLUTERS.has(seg))) {
    throw new Error(
      `Refusing to set a prototype-polluting path: ${JSON.stringify(path)}`
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
