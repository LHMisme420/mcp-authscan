import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const script = path.join(root, 'scripts/deployment-build.sh');

async function buildFixture(failAt = '') {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'vata-build-'));
  const trace = path.join(temp, 'trace.jsonl');
  const prefix = path.join(temp, '.pythonlibs');
  const stub = `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const tool = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const step = tool === 'npm' ? 'npm-' + args[0]
  : tool === 'uv' ? 'uv-install' : 'python-prefix';
fs.appendFileSync(process.env.FIXTURE_TRACE, JSON.stringify({
  step, args, cwd: process.cwd(), pipUser: process.env.PIP_USER || null,
}) + '\\n');
if (step === process.env.FIXTURE_FAIL_AT) process.exit(17);
if (step === 'python-prefix') console.log(process.env.FIXTURE_PREFIX);
`;
  try {
    for (const tool of ['npm', 'python3', 'uv']) {
      await writeFile(path.join(temp, tool), stub, { mode: 0o755 });
    }
    const result = spawnSync('bash', [script], {
      cwd: temp,
      encoding: 'utf8',
      env: {
        PATH: `${temp}:${process.env.PATH}`,
        HOME: temp,
        PYTHONNOUSERSITE: 'true',
        PIP_USER: '1',
        FIXTURE_TRACE: trace,
        FIXTURE_PREFIX: prefix,
        FIXTURE_FAIL_AT: failAt,
      },
    });
    const calls = (await readFile(trace, 'utf8')).trim().split('\n').map(line => JSON.parse(line));
    return { result, calls, prefix, python: path.join(temp, 'python3') };
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

test('hosting uses an explicit build without changing the durable runtime command', async () => {
  const config = await readFile(path.join(root, '.replit'), 'utf8');
  assert.match(config, /\[packager\.features\]\s+enabledForHosting = false/);
  assert.match(config, /build = \["bash", "scripts\/deployment-build\.sh"\]/);
  assert.match(config, /deploymentTarget = "(?:cloudrun|autoscale)"/);
  assert.match(config, /run = \["env", "VATA_SQLITE_DURABILITY=postgres", "DB_FILE=\/tmp\/vata-findings\.sqlite", "npm", "run", "start"\]/);
  const modules = config.match(/^modules = (.+)$/m)?.[1] ?? '';
  assert.match(modules, /"python-base-3\.11"/);
  assert.doesNotMatch(modules, /"python-\d/);
  assert.match(config, /packages = \[[^\n]*"uv"/);
});

test('shared Python configuration retains the managed library directory', async () => {
  const config = await readFile(path.join(root, '.replit'), 'utf8');
  const shared = config.match(/\[userenv\.shared\]([\s\S]*?)(?=\n\[|$)/)?.[1] ?? '';
  assert.match(shared, /^PYTHONUSERBASE\s*=\s*"\.pythonlibs"$/m);
  assert.match(shared, /^PIP_PREFIX\s*=\s*"\.pythonlibs"$/m);
  assert.match(shared, /^PIP_USER\s*=\s*"0"$/m);
  assert.match(shared, /^UV_PROJECT_ENVIRONMENT\s*=\s*"\.pythonlibs"$/m);
  assert.match(shared, /^UV_PYTHON_DOWNLOADS\s*=\s*"never"$/m);
  assert.match(shared, /^UV_PYTHON_PREFERENCE\s*=\s*"only-system"$/m);
});

test('Python runtime dependencies are explicit, without the legacy hosting pip manifest', async () => {
  await assert.rejects(readFile(path.join(root, 'requirements.txt')), { code: 'ENOENT' });
  await assert.rejects(readFile(path.join(root, 'pyproject.toml')), { code: 'ENOENT' });
  await assert.rejects(readFile(path.join(root, 'uv.lock')), { code: 'ENOENT' });
  const requirements = await readFile(path.join(root, 'requirements-runtime.txt'), 'utf8');
  assert.match(requirements, /^flask>=3\.1\.3,<4$/m);
  assert.match(requirements, /^gunicorn$/m);
});

test('web root stays separate from the nested CLI package and retains runtime requirements', async () => {
  const ignore = await readFile(path.join(root, '.replitignore'), 'utf8');
  const rules = ignore.split('\n').map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
  assert.ok(rules.includes('/pyproject.toml'));
  assert.ok(rules.includes('/uv.lock'));
  assert.ok(!rules.includes('/requirements-runtime.txt'));
  assert.ok(!rules.includes('requirements-runtime.txt'));
  const project = await readFile(path.join(root, 'mcp_authscan', 'pyproject.toml'), 'utf8');
  assert.match(project, /\[project\]/, 'CLI packaging must remain available in the repository');
  assert.match(project, /package-dir = \{mcp_authscan = "\."\}/);
});

test('post-merge verification remains offline and read-only without importing pip', async () => {
  const hook = await readFile(path.join(root, 'scripts/post-merge.sh'), 'utf8');
  assert.doesNotMatch(hook, /python3 -m pip/);
  assert.match(hook, /uv pip install --dry-run --no-index --no-cache --prefix/);
});

test('canonical scanner compiles and retains the discovery security parameter', () => {
  const result = spawnSync('python3', ['-c', [
    'import ast, pathlib',
    'path = pathlib.Path("mcp_authscan/scan_main.py")',
    'source = path.read_text()',
    'compile(source, str(path), "exec")',
    'tree = ast.parse(source)',
    'functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "discover_oauth_endpoints"]',
    'assert len(functions) == 1',
    'assert [arg.arg for arg in functions[0].args.args] == ["base_url", "allow_private"]',
  ].join('\n')], {
    cwd: root,
    encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C.UTF-8' },
  });
  assert.equal(result.status, 0, result.stderr);
});

test('build installs Node and Python into the managed prefix before compiling', async () => {
  const { result, calls, prefix, python } = await buildFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(calls.map(call => call.step), ['npm-ci', 'python-prefix', 'uv-install', 'npm-run']);
  assert.deepEqual(calls[0].args, ['ci', '--include=dev']);
  assert.deepEqual(calls[2].args,
    ['pip', 'install', '--reinstall', '--prefix', prefix, '--python', python, '--requirement', 'requirements-runtime.txt']);
  assert.equal(calls[2].pipUser, '1', 'UV prefix installation must not depend on changing pip user mode');
  assert.deepEqual(calls[3].args, ['run', 'build']);
  for (const call of calls) {
    assert.equal(call.cwd, path.resolve(root));
    assert.ok(!call.args.includes('--break-system-packages'));
    assert.ok(!call.args.includes('--user'));
  }
});

for (const failAt of ['npm-ci', 'python-prefix', 'uv-install']) {
  test(`failed ${failAt} prevents later build steps`, async () => {
    const { result, calls } = await buildFixture(failAt);
    assert.equal(result.status, 17);
    assert.equal(calls.at(-1).step, failAt);
    assert.ok(!calls.some(call => call.step === 'npm-run'));
  });
}
