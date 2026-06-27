'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
// Uses lodash.set with a user-controlled path — the reachable sink for
// GHSA-p6mc-m468-83gw / CVE-2020-8203 (prototype pollution). The standalone
// `lodash.set` package has NO patched release (every version up to and
// including 4.3.2 is affected), so a version bump cannot fix this. Instead we
// guard the sink: any update path whose segments include a prototype-polluting
// key (`__proto__`, `constructor`, `prototype`) is rejected before lodash.set
// runs, so Object.prototype can never be mutated by user input.
const set = require('lodash.set');

const POLLUTERS = new Set(['__proto__', 'constructor', 'prototype']);

// Normalize a lodash path (string dot/bracket notation OR array) into segments.
function pathSegments(path) {
  if (Array.isArray(path)) return path.map((s) => String(s));
  return String(path)
    // Convert bracket access (a[0], a['x'], a[__proto__]) into dot access.
    .replace(/\[(?:"([^"]*)"|'([^']*)'|([^\]]*))\]/g, '.$1$2$3')
    .split('.')
    .filter((s) => s.length > 0);
}

function assertSafePath(path) {
  for (const segment of pathSegments(path)) {
    if (POLLUTERS.has(segment)) {
      throw new Error(
        `Refusing to set prototype-polluting path segment "${segment}" (GHSA-p6mc-m468-83gw)`,
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
