'use strict';
// Applies a batch of user-supplied field updates to a billing profile.
// lodash.set (GHSA-p6mc-m468-83gw) has NO patched release, so we cannot bump it.
// Patchwork mitigates the prototype-pollution sink in first-party code instead.
const set = require('lodash.set');

const POLLUTERS = new Set(['__proto__', 'constructor', 'prototype']);

function isPolluting(path) {
  const segments = Array.isArray(path) ? path : String(path).split('.');
  return segments.some((s) => POLLUTERS.has(s));
}

function applyUpdates(profile, updates) {
  const target = profile || {};
  for (const { path, value } of updates) {
    if (isPolluting(path)) {
      throw new Error('Refusing to set a prototype-polluting path: ' + path);
    }
    set(target, path, value);
  }
  return target;
}

module.exports = { applyUpdates };
