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
  : args[0] === '-c' ? 'python-prefix' : 'python-install';
fs.appendFileSync(process.env.FIXTURE_TRACE, JSON.stringify({
  step, args, cwd: process.cwd(), pipUser: process.env.PIP_USER || null,
}) + '\\n');
if (step === process.env.FIXTURE_FAIL_AT) process.exit(17);
if (step === 'python-prefix') console.log(process.env.FIXTURE_PREFIX);
`;
  try {
    for (const tool of ['npm', 'python3']) {
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
    return { result, calls, prefix };
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
});

test('build installs Node and Python into the managed prefix before compiling', async () => {
  const { result, calls, prefix } = await buildFixture();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(calls.map(call => call.step), ['npm-ci', 'python-prefix', 'python-install', 'npm-run']);
  assert.deepEqual(calls[0].args, ['ci', '--include=dev']);
  assert.deepEqual(calls[2].args,
    ['-m', 'pip', 'install', '--prefix', prefix, '--requirement', 'requirements.txt']);
  assert.equal(calls[2].pipUser, '0', 'Inherited user-install mode must not override the explicit prefix');
  assert.deepEqual(calls[3].args, ['run', 'build']);
  for (const call of calls) {
    assert.equal(call.cwd, path.resolve(root));
    assert.ok(!call.args.includes('--break-system-packages'));
    assert.ok(!call.args.includes('--user'));
  }
});

for (const failAt of ['npm-ci', 'python-prefix', 'python-install']) {
  test(`failed ${failAt} prevents later build steps`, async () => {
    const { result, calls } = await buildFixture(failAt);
    assert.equal(result.status, 17);
    assert.equal(calls.at(-1).step, failAt);
    assert.ok(!calls.some(call => call.step === 'npm-run'));
  });
}
