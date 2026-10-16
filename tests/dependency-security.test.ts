import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

test('resolved dependency graph contains no vulnerable braces or old uuid', () => {
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  const packages = Object.entries(lock.packages) as [string, { version?: string }][];
  assert.equal(packages.some(([name]) => name.endsWith('/braces')), false);
  assert.equal(packages.some(([name]) => name.endsWith('/http-proxy-middleware')), false);
  const uuidEntries = packages.filter(([name]) => name.endsWith('/uuid'));
  assert.ok(uuidEntries.length > 0);
  for (const [, value] of uuidEntries) {
    const [major, minor, patch] = value.version!.split('.').map(Number);
    assert.ok(major === 11 && (minor > 1 || minor === 1 && patch >= 1), `Expected patched CommonJS-compatible uuid, got ${value.version}`);
  }
});

test('patched uuid retains CommonJS v4 compatibility and rejects truncated v3/v5/v6 output', () => {
  const { v3, v4, v5, v6, validate } = require('uuid');
  assert.equal(validate(v4()), true);
  const namespace = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
  for (const fn of [
    () => v3('fixture', namespace, new Uint8Array(8), 4),
    () => v5('fixture', namespace, new Uint8Array(8), 4),
    () => v6({}, new Uint8Array(8), 4),
  ]) assert.throws(fn, RangeError);
});
