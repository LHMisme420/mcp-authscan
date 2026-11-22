// Regression tests for the exact-value allowlist in scripts/public-push-check.mjs.
// Each test builds a throwaway repository; no network. Credential-like values are
// assembled at runtime so this file itself never contains one.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const GUARD = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'public-push-check.mjs');
const VALUE = ['Qz7x', 'Rm2L', 'p9Wv', '4Kt8', 'Hn3B', 'f6Yc'].join('');
const PROVIDER = ['sk', 'live', ['AbCd', 'EfGh', 'IjKl', 'MnOp', 'QrSt', 'UvWx'].join('')].join('_');
const sha = v => createHash('sha256').update(v, 'utf8').digest('hex');

function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), 'ppa-'));
  const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q', '-b', 'main');
  g('config', 'user.email', 't@example.invalid');
  g('config', 'user.name', 't');
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  }
  g('add', '-A');
  g('commit', '-q', '-m', 'fixture');
  g('remote', 'add', 'origin', 'https://example.invalid/r.git');
  return dir;
}

function guard(dir, env = {}) {
  return spawnSync('node', [GUARD, '--remote', 'origin', '--branch', 'main', '--target', 'main', '--new-branch'],
    { cwd: dir, encoding: 'utf8', env: { ...process.env, ...env } });
}

test('a credential-like assignment is blocked without an allowlist entry', () => {
  const r = guard(repo({ 'src.py': `client_secret = "${VALUE}"\n` }));
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /"src\.py"\tliteral-credential/);
});

test('the exact allowlisted value passes', () => {
  const r = guard(repo({
    'src.py': `client_secret = "${VALUE}"\n`,
    'scripts/public-push-allowlist.txt': `${sha(VALUE)}  # src.py fixture\n`,
  }));
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /PASS/);
});

test('a one-character change to an allowlisted value is blocked again', () => {
  const r = guard(repo({
    'src.py': `client_secret = "${VALUE}Z"\n`,
    'scripts/public-push-allowlist.txt': `${sha(VALUE)}\n`,
  }));
  assert.equal(r.status, 1, r.stdout + r.stderr);
});

test('a provider-shaped token stays blocked even when its hash is allowlisted', () => {
  const r = guard(repo({
    'src.py': `api_key = "${PROVIDER}"\n`,
    'scripts/public-push-allowlist.txt': `${sha(PROVIDER)}\n`,
  }));
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /literal-credential/);
});

test('an allowlist only on an unpushed working copy does not count', () => {
  const dir = repo({ 'src.py': `client_secret = "${VALUE}"\n` });
  mkdirSync(join(dir, 'scripts'), { recursive: true });
  writeFileSync(join(dir, 'scripts/public-push-allowlist.txt'), `${sha(VALUE)}\n`);
  assert.equal(guard(dir).status, 1);
});

test('candidate listing prints hash, length and a 6-character prefix, never the value', () => {
  const r = guard(repo({ 'src.py': `client_secret = "${VALUE}"\n` }), { PUBLIC_PUSH_LIST_CANDIDATES: '1' });
  assert.match(r.stderr, new RegExp(`CANDIDATE\\t"src\\.py"\\t${sha(VALUE)}\\tlen=${VALUE.length}\\tstarts="${VALUE.slice(0, 6)}"`));
  assert.ok(!r.stderr.includes(VALUE) && !r.stdout.includes(VALUE));
});
