import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('../scripts/public-push-check.mjs', import.meta.url));

function fixture(t) {
  const cwd = mkdtempSync(join(tmpdir(), 'public-push-fixture-'));
  t.after(() => rmSync(cwd, { recursive: true, force: true }));
  // Isolate from user Git config, hooks, signing, and any surrounding repository.
  const env = { PATH: process.env.PATH, HOME: cwd, GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' };
  const git = (...args) => {
    const result = spawnSync('git', args, { cwd, env, encoding: 'utf8' });
    assert.equal(result.status, 0, 'fixture Git command failed');
    return result.stdout.trim();
  };
  const write = (path, value) => {
    mkdirSync(dirname(join(cwd, path)), { recursive: true });
    writeFileSync(join(cwd, path), value);
  };
  const commit = (message = 'fixture change') => {
    git('add', '-A');
    git('commit', '-qm', message);
  };
  git('init', '-q', '-b', 'release/source-only');
  git('config', 'user.name', 'Fixture');
  git('config', 'user.email', 'fixture@example.invalid');
  // No actual remote exists; guard must not access the network.
  git('remote', 'add', 'origin', join(cwd, 'nonexistent-remote.git'));
  write('README.md', 'Safe source fixture\n');
  commit('public baseline');
  git('update-ref', 'refs/remotes/origin/main', 'HEAD');
  const check = (extra = [], replace = false) => spawnSync(process.execPath, [
    script, ...(replace ? [] : ['--remote', 'origin', '--branch', 'release/source-only', '--target', 'main']),
    ...extra,
  ], { cwd, env, encoding: 'utf8' });
  return { cwd, git, write, commit, check };
}

function blocked(result, path, category, values = []) {
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.ok(result.stdout.includes(`${JSON.stringify(path)}\t${category}`));
  for (const value of values) assert.ok(!(result.stdout + result.stderr).includes(value), 'value leaked');
}

test('database added then removed is rejected across the outgoing commit range', t => {
  const f = fixture(t);
  f.write('private/findings.sqlite3', 'synthetic database');
  f.commit('add database');
  f.git('rm', 'private/findings.sqlite3');
  f.commit('remove database');
  blocked(f.check(), 'private/findings.sqlite3', 'database-path');
});

test('ignored but already tracked database remains blocked even when inherited from baseline', t => {
  const f = fixture(t);
  f.write('tracked.db', 'synthetic');
  f.commit();
  f.git('update-ref', 'refs/remotes/origin/main', 'HEAD');
  f.write('.gitignore', '*.db\n');
  f.commit();
  blocked(f.check(), 'tracked.db', 'database-path');
});

test('safe source passes and no files, index, refs, or history are changed', t => {
  const f = fixture(t);
  f.write('src/index.js', 'export const key = process.env.API_KEY;\n');
  f.commit();
  f.write('untracked.db', 'local-only file');
  const before = [f.git('status', '--porcelain'), f.git('show-ref'), f.git('ls-files', '--stage')];
  const result = f.check();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.deepEqual([f.git('status', '--porcelain'), f.git('show-ref'), f.git('ls-files', '--stage')], before);
  assert.equal(readFileSync(join(f.cwd, 'untracked.db'), 'utf8'), 'local-only file');
});

test('known dummy values and safe environment templates pass', t => {
  const f = fixture(t);
  f.write('tests/examples.js', [
    'const access_token = "AKIAIOSFODNN7EXAMPLE";',
    'const secret = "not-a-real-secret-for-tests";',
    'const api_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";',
    'const password = "<replace-with-your-password>";',
  ].join('\n'));
  f.write('.env.example', 'API_KEY=your-api-key-here\n');
  f.commit();
  assert.equal(f.check().status, 0);
});

test('renamed SQLite payload is blocked without exposing data', t => {
  const f = fixture(t);
  const content = 'SQLite format 3\0synthetic-private-marker';
  f.write('assets/cache.bin', content);
  f.commit();
  blocked(f.check(), 'assets/cache.bin', 'sqlite-content', ['synthetic-private-marker']);
});

test('environment and private-key paths are blocked', t => {
  const f = fixture(t);
  f.write('.env.production.local', 'SAMPLE=synthetic-marker');
  f.write('keys/id_ed25519', 'synthetic-marker');
  f.commit();
  blocked(f.check(), '.env.production.local', 'environment-or-credential-file', ['synthetic-marker']);
  blocked(f.check(), 'keys/id_ed25519', 'private-key-file');
});

test('private-key content is detected under an innocent filename', t => {
  const f = fixture(t);
  f.write('notes.txt', ['-----BEGIN ' + 'RSA PRIVATE KEY-----', 'synthetic-key-content'].join('\n'));
  f.commit();
  blocked(f.check(), 'notes.txt', 'private-key-content', ['synthetic-key-content']);
});

test('literal provider credentials and quoted assignments are blocked and redacted', t => {
  const f = fixture(t);
  // Synthetic formats assembled here, never taken from workspace credentials.
  const provider = 'ghp_' + 'Ab9Cd8Ef7Gh6Ij5Kl4Mn3Op2Qr1St0Uv9Wx8';
  const generic = 'Q7z!m2R9#pL4@vT6$xN8';
  f.write('tests/credentials.js', `const api_key = "${provider}";\n`);
  f.write('config.js', `const secret = "${generic}";\n`);
  f.commit();
  const result = f.check();
  blocked(result, 'tests/credentials.js', 'literal-credential', [provider, generic]);
  blocked(result, 'config.js', 'literal-credential', [provider, generic]);
});

test('template names do not exempt credential contents', t => {
  const f = fixture(t);
  const value = 'AKIA' + '9Z8Y7X6W5V4U3T2S';
  f.write('.env.example', `AWS_ACCESS_KEY_ID=${value}\n`);
  f.commit();
  blocked(f.check(), '.env.example', 'literal-credential', [value]);
});

test('credentials removed in later commits are still blocked', t => {
  const f = fixture(t);
  const value = 'sk_live_' + 'Ab9Cd8Ef7Gh6Ij5Kl4Mn3Op2';
  f.write('config.js', `const key = "${value}";`);
  f.commit();
  f.write('config.js', 'const key = process.env.KEY;');
  f.commit();
  blocked(f.check(), 'config.js', 'literal-credential', [value]);
});

test('merge-side history is inspected even if the merge tip removed the database', t => {
  const f = fixture(t);
  f.git('checkout', '-qb', 'feature');
  f.write('side.db', 'synthetic');
  f.commit();
  f.git('rm', 'side.db');
  f.commit();
  f.git('checkout', '-q', 'release/source-only');
  f.write('source.js', 'export const safe = true;');
  f.commit();
  f.git('merge', '--no-ff', '-qm', 'merge source changes', 'feature');
  blocked(f.check(), 'side.db', 'database-path');
});

test('new branches inspect full ancestry, including previously removed databases', t => {
  const f = fixture(t);
  f.write('old.db', 'synthetic');
  f.commit();
  f.git('rm', 'old.db');
  f.commit();
  blocked(f.check(['--remote', 'origin', '--branch', 'release/source-only',
    '--target', 'release/new', '--new-branch'], true), 'old.db', 'database-path');
});

test('private source and destination branches and bulk/force flags are rejected', t => {
  const f = fixture(t);
  for (const branch of ['backup/local-copy', 'private/findings', 'local-history/snapshot']) {
    f.git('branch', branch);
    const result = f.check(['--remote', 'origin', '--branch', branch, '--target', 'main'], true);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /private-backup-branch/);
  }
  assert.equal(f.check(['--remote', 'origin', '--branch', 'release/source-only', '--target', 'backup/history'], true).status, 2);
  for (const flag of ['--all', '--mirror', '--force', '--force-with-lease']) {
    const result = f.check([flag]);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /invalid-arguments/);
  }
});

test('missing baseline, missing branch, duplicate arguments and nonexistent remote fail closed', t => {
  const f = fixture(t);
  for (const args of [
    [],
    ['--remote', 'origin', '--branch', 'release/source-only', '--target', 'missing'],
    ['--remote', 'origin', '--branch', 'missing', '--target', 'main'],
    ['--remote', 'missing', '--branch', 'release/source-only', '--target', 'main'],
  ]) assert.equal(f.check(args, true).status, 2);
  assert.equal(f.check(['--remote', 'origin']).status, 2);
  assert.equal(f.check(['--new-branch']).status, 2);
});

test('Git errors never relay remote URLs or their embedded synthetic credentials', t => {
  const f = fixture(t);
  const marker = 'synthetic-private-url-marker';
  const result = f.check(['--remote', `https://user:${marker}@example.invalid`,
    '--branch', 'release/source-only', '--target', 'main'], true);
  assert.equal(result.status, 2);
  assert.ok(!(result.stderr + result.stdout).includes(marker));
});

test('paths are escaped, not executable terminal control sequences', t => {
  const f = fixture(t);
  const path = 'odd\n\u001b[31m.sqlite';
  f.write(path, 'synthetic');
  f.commit();
  const result = f.check();
  blocked(result, path, 'database-path');
  assert.ok(!result.stdout.includes('\u001b'));
  assert.equal(result.stdout.trim().split('\n').length, 1);
});

test('LFS pointer and submodule content fail closed', t => {
  const f = fixture(t);
  f.write('asset.bin', 'version https://git-lfs.github.com/spec/v1\noid sha256:123\nsize 123\n');
  f.git('add', 'asset.bin');
  f.git('update-index', '--add', '--cacheinfo', `160000,${f.git('rev-parse', 'HEAD')},vendor/module`);
  f.git('commit', '-qm', 'external content');
  const result = f.check();
  blocked(result, 'asset.bin', 'unverified-lfs-content');
  blocked(result, 'vendor/module', 'unverified-submodule');
});

test('replacement objects cannot hide sensitive committed content', t => {
  const f = fixture(t);
  f.write('hidden.db', 'synthetic');
  f.commit();
  const unsafe = f.git('rev-parse', 'HEAD');
  f.git('rm', 'hidden.db');
  f.commit();
  const safe = f.git('rev-parse', 'HEAD');
  f.git('replace', unsafe, safe);
  blocked(f.check(), 'hidden.db', 'database-path');
});

test('oversized blobs fail closed without loading their contents', t => {
  const f = fixture(t);
  f.write('large.bin', '');
  truncateSync(join(f.cwd, 'large.bin'), 64 * 1024 * 1024 + 1);
  f.commit();
  blocked(f.check(), 'large.bin', 'unverified-oversized-blob');
});

test('shallow histories cannot silently omit older sensitive commits', t => {
  const f = fixture(t);
  f.write('.git/shallow', `${f.git('rev-parse', 'HEAD')}\n`);
  const result = f.check();
  assert.equal(result.status, 2);
  assert.match(result.stderr, /incomplete-shallow-history/);
});

test('guard and its regression fixtures are themselves safe source-only files', t => {
  const f = fixture(t);
  f.write('scripts/public-push-check.mjs', readFileSync(script));
  f.write('tests/public-push-check.test.mjs', readFileSync(fileURLToPath(import.meta.url)));
  f.commit();
  const result = f.check();
  assert.equal(result.status, 0, result.stdout + result.stderr);
});
