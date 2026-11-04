#!/usr/bin/env node
// Read Git objects only: never read working-tree files, credentials, or secret values.
import { spawnSync } from 'node:child_process';

const MAX_BUFFER = 64 * 1024 * 1024;
function git(args) {
  const result = spawnSync('git', ['--no-replace-objects', ...args], { maxBuffer: MAX_BUFFER });
  // Git errors can contain credential-bearing URLs or file contents. Never relay them.
  if (result.error || result.status !== 0) throw new Error('git-read-failed');
  return result.stdout;
}

function options(args) {
  const parsed = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    if (!['--remote', '--branch', '--target', '--new-branch'].includes(key) || key in parsed) {
      throw new Error('invalid-arguments');
    }
    if (key === '--new-branch') {
      parsed[key] = true;
      i--;
    } else {
      const value = args[i + 1];
      if (!value || value.startsWith('-')) throw new Error('invalid-arguments');
      parsed[key] = value;
    }
  }
  if (!parsed['--remote'] || !parsed['--branch'] || !parsed['--target']) {
    throw new Error('explicit-destination-required');
  }
  return parsed;
}

function privateBranch(branch) {
  return /(^|[/_.-])(backup|backups|private|local)([/_.-]|$)/i.test(branch);
}

function pathCategories(path) {
  const categories = [];
  if (/\.(?:db|sqlite|sqlite3)(?:[-.].*)?$/i.test(path)
      || /\.(?:dump|vata-dr)$/i.test(path)
      || /(^|\/)(?:runtime-data|\.vata-recovery-[^/]*|\.vata-restore-[^/]*)(\/|$)/i.test(path)
      || /(^|\/)vata_findings_backup\.json$/i.test(path)) categories.push('database-path');
  const name = path.split('/').at(-1);
  if ((/^\.env(?:[.-].*)?$/i.test(name) && !/^\.env\.(?:example|sample|template)$/i.test(name))
      || /^(?:\.envrc|\.netrc|\.npmrc|credentials(?:\.json)?)$/i.test(name)
      || /(^|\/)\.aws\/credentials$/i.test(path)) categories.push('environment-or-credential-file');
  if (/\.(?:pem|key|p12|pfx|jks|keystore)$/i.test(name)
      || /^id_(?:rsa|dsa|ecdsa|ed25519)$/i.test(name)) categories.push('private-key-file');
  return categories;
}

// Narrow, explicit examples, not an exemption for all tests or all "test_*" values.
const DUMMY_VALUES = new Set([
  'your-api-key-here', 'your_api_key_here', 'replace-with-your-secret',
  'this-is-a-test-secret', 'test-secret-at-least-32-characters',
  'AKIAIOSFODNN7EXAMPLE',
  'not-a-real-secret-for-tests',
  'dummy-secret-for-testing-only',
]);
function dummy(value) {
  return DUMMY_VALUES.has(value)
    || /^(?:x{8,}|0{8,}|a{8,}|\*{8,}|<[^<>\r\n]+>)$/i.test(value);
}

function contentCategories(blob) {
  const categories = [];
  if (blob.subarray(0, 16).equals(Buffer.from('SQLite format 3\0'))) categories.push('sqlite-content');
  const text = blob.toString('utf8');
  if (/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(text)) categories.push('private-key-content');
  const tokens = text.matchAll(
    /\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255}|[sr]k_live_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35})\b/g,
  );
  if ([...tokens].some(match => !dummy(match[0]))) categories.push('literal-credential');
  // Quoted assignments only; references to process.env / os.environ are not literals.
  const assignments = text.matchAll(
    /(?:["']?)(?:[A-Za-z0-9_]*(?:api[_-]?key|secret|password|access[_-]?token|auth[_-]?token)[A-Za-z0-9_]*)(?:["']?)\s*[:=]\s*(["'])([^"'\r\n]{20,})\1/gi,
  );
  for (const match of assignments) {
    const value = match[2];
    if (!dummy(value) && !/\s|\$\{|process\.env|os\.environ|https?:\/\//.test(value)
        && /^[A-Za-z0-9_+/=.!@#$%^&*-]+$/.test(value)
        && new Set(value).size >= 12) {
      categories.push('literal-credential');
      break;
    }
  }
  return [...new Set(categories)];
}

function main() {
  const args = options(process.argv.slice(2));
  const remote = args['--remote'];
  const branch = args['--branch'];
  const target = args['--target'];
  if (git(['rev-parse', '--is-shallow-repository']).toString().trim() !== 'false') {
    throw new Error('incomplete-shallow-history');
  }
  if (privateBranch(branch) || privateBranch(target)) throw new Error('private-backup-branch');
  for (const ref of [`refs/heads/${branch}`, `refs/heads/${target}`, `refs/remotes/${remote}/${target}`]) {
    git(['check-ref-format', ref]);
  }
  // Validate the named remote without reading its URL or contacting it.
  if (!git(['remote']).toString().trim().split('\n').includes(remote)) throw new Error('unknown-remote');
  const head = git(['rev-parse', '--verify', `refs/heads/${branch}^{commit}`]).toString().trim();
  const trackingRef = `refs/remotes/${remote}/${target}`;
  let base;
  try {
    base = git(['rev-parse', '--verify', `${trackingRef}^{commit}`]).toString().trim();
  } catch {
    if (!args['--new-branch']) throw new Error('fetch-target-first-or-declare-new-branch');
  }
  if (base && args['--new-branch']) throw new Error('new-branch-already-exists');
  // New public branches expose ALL ancestry. Existing branches expose every
  // commit not reachable from the explicitly selected destination, including merges.
  const commits = git(['rev-list', head, ...(base ? [`^${base}`] : [])])
    .toString().trim().split('\n').filter(Boolean);
  const blobs = new Map();
  const findings = new Map();
  function report(path, category) {
    const key = JSON.stringify([path, category]);
    findings.set(key, [path, category]);
  }
  // Also inspect the tip when nothing is outgoing. .gitignore never excuses a
  // tracked file. Trees (not diffs alone) catch unchanged tracked sensitive files.
  for (const commit of new Set([head, ...commits])) {
    const tree = git(['ls-tree', '-r', '-z', commit]).toString('utf8');
    for (const entry of tree.split('\0').filter(Boolean)) {
      const tab = entry.indexOf('\t');
      const [mode, type, oid] = entry.slice(0, tab).split(' ');
      const path = entry.slice(tab + 1);
      for (const category of pathCategories(path)) report(path, category);
      // Submodule content cannot be verified from this repository.
      if (mode === '160000') report(path, 'unverified-submodule');
      if (type !== 'blob') continue;
      if (!blobs.has(oid)) blobs.set(oid, new Set());
      blobs.get(oid).add(path);
    }
  }
  for (const [oid, paths] of blobs) {
    const size = Number(git(['cat-file', '-s', oid]).toString().trim());
    if (!Number.isSafeInteger(size) || size > MAX_BUFFER) {
      for (const path of paths) report(path, 'unverified-oversized-blob');
      continue;
    }
    const blob = git(['cat-file', 'blob', oid]);
    const categories = contentCategories(blob);
    if (blob.subarray(0, 100).toString().startsWith('version https://git-lfs.github.com/spec/v1')) {
      categories.push('unverified-lfs-content');
    }
    for (const path of paths) for (const category of categories) report(path, category);
  }
  for (const [path, category] of [...findings.values()].sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]))) {
    // JSON escaping prevents terminal control characters/newlines in Git paths.
    console.log(`${JSON.stringify(path)}\t${category}`);
  }
  if (findings.size) process.exitCode = 1;
  else console.log('PASS\tpublic-push-check');
}

try {
  main();
} catch (error) {
  // Only controlled categories are printed; never the underlying Git stderr.
  const allowed = new Set([
    'invalid-arguments', 'explicit-destination-required', 'git-read-failed',
    'private-backup-branch', 'unknown-remote', 'fetch-target-first-or-declare-new-branch',
    'new-branch-already-exists',
    'incomplete-shallow-history',
  ]);
  console.error(`BLOCKED\t${allowed.has(error.message) ? error.message : 'check-failed'}`);
  process.exitCode = 2;
}
