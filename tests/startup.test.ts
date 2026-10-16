import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { mkdtemp, readFile, rm, mkdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
import pg from 'pg';

const root = process.cwd();
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function freePort() {
  const socket = net.createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = (socket.address() as net.AddressInfo).port;
  await new Promise<void>(resolve => socket.close(() => resolve()));
  return port;
}
// Allowlist, not an environment spread: never send workspace credentials to fixtures.
const tools = {
  PATH: process.env.PATH!, HOME: process.env.HOME!, LANG: 'C.UTF-8',
  PYTHONPATH: path.join(root, '.pythonlibs/lib/python3.11/site-packages'),
};
function tool(command: string, args: string[]) {
  return execFileSync(command, args, { env: tools, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

// Leave headroom for the complete multi-process suite on a shared host.
// Each individual failure/readiness deadline below remains unchanged.
test('built npm start uses isolated PostgreSQL and private Flask with safe failures', { timeout: 240000 }, async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'vata-startup-'));
  const pgPort = await freePort();
  const pgData = path.join(temp, 'postgres');
  let pgStarted = false;
  let admin: pg.Client | undefined;
  const children = new Set<ChildProcess>();
  async function cleanup(child: ChildProcess) {
    try { process.kill(-child.pid!, 'SIGTERM'); } catch { return; }
    for (let i = 0; i < 70; i++) {
      await delay(100);
      try { process.kill(-child.pid!, 0); } catch { return; }
    }
    try { process.kill(-child.pid!, 'SIGKILL'); } catch {}
  }
  t.after(async () => {
    await Promise.all([...children].map(cleanup));
    await admin?.end();
    if (pgStarted) tool('pg_ctl', ['-D', pgData, '-m', 'immediate', '-w', 'stop']);
    await rm(temp, { recursive: true, force: true });
  });
  // These binaries must be present; missing prerequisites are failures, never skips.
  tool('initdb', ['-D', pgData, '-A', 'trust', '-U', 'fixture_owner', '--no-locale']);
  tool('pg_ctl', ['-D', pgData, '-l', path.join(temp, 'postgres.log'),
    '-o', `-h 127.0.0.1 -p ${pgPort} -k ${temp}`, '-w', 'start']);
  pgStarted = true;
  const databaseUrl = `postgresql://startup_reader@127.0.0.1:${pgPort}/postgres`;
  admin = new pg.Client({ connectionString: `postgresql://fixture_owner@127.0.0.1:${pgPort}/postgres` });
  await admin.connect();
  await admin.query(await readFile('tests/fixtures/startup-schema.sql', 'utf8'));

  async function launch(overrides: Record<string, string | undefined> = {}) {
    const port = await freePort();
    let scannerPort = await freePort();
    while (scannerPort === port) scannerPort = await freePort();
    const env: Record<string, string | undefined> = {
      ...tools, HOME: temp, DATABASE_URL: databaseUrl,
      CLERK_PUBLISHABLE_KEY: `pk_test_${Buffer.from('fixture.clerk.accounts.dev$').toString('base64')}`,
      CLERK_SECRET_KEY: 'sk_test_fixture_not_a_real_key',
      JWT_SECRET: 'fixture-only-signing-key-at-least-32-characters',
      PUBLIC_APP_URL: 'https://fixture.invalid',
      DB_FILE: path.join(temp, `scanner-${scannerPort}.sqlite`),
      VATA_SQLITE_DURABILITY: 'local', // Explicitly ephemeral, isolated fixture only.
      // The explicit app port wins over an unrelated imported PORT value.
      PORT: '1', VATA_PORT: String(port), VATA_SCANNER_PORT: String(scannerPort),
      ...overrides,
    };
    const child = spawn('npm', ['start'], { cwd: root, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    children.add(child);
    let output = '';
    child.stdout!.on('data', data => { output += data; });
    child.stderr!.on('data', data => { output += data; });
    child.on('error', error => { output += error.message; });
    return { child, port, scannerPort, output: () => output };
  }
  async function exited(run: Awaited<ReturnType<typeof launch>>, timeoutMs = 12000) {
    for (let i = 0; i < timeoutMs / 100; i++) {
      if (run.child.exitCode !== null || run.child.signalCode !== null) {
        assert.notEqual(run.child.exitCode, 0, run.output());
        return run.output();
      }
      await delay(100);
    }
    assert.fail(`npm start did not exit on startup failure:\n${run.output()}`);
  }
  async function healthy(run: Awaited<ReturnType<typeof launch>>, live = false) {
    for (let i = 0; i < 250; i++) {
      assert.equal(run.child.exitCode, null, run.output());
      try {
        const response = await fetch(`http://127.0.0.1:${run.port}/health`, { signal: AbortSignal.timeout(500) });
        if (response.status === 200) {
          for (const paymentPath of (live
            ? ['/api/test-checkout', '/api/test-checkout/webhook']
            : ['/api/checkout', '/api/test-checkout', '/api/test-checkout/webhook', '/api/billing/status', '/api/stripe/webhook'])) {
            const blocked = await fetch(`http://127.0.0.1:${run.port}${paymentPath}`, { method: 'POST' });
            assert.equal(blocked.status, 410, 'Production must reject test checkout without consulting Stripe.');
          }
          return response;
        }
      } catch {}
      await delay(100);
    }
    assert.fail(`npm start did not become ready:\n${run.output()}`);
  }
  await t.test('missing URL fails without local PostgreSQL fallback or credential output', async () => {
    const run = await launch({ DATABASE_URL: undefined });
    assert.match(await exited(run), /DATABASE_URL is missing.*Publish/);
    await assert.rejects(fetch(`http://127.0.0.1:${run.port}/health`));
  });
  await t.test('explicit live mode exposes only the signed callback and setup failures cannot block HTTP readiness', async () => {
    const run = await launch({ VATA_BILLING_MODE: 'live', VATA_PREPARE_LIVE_BILLING: '1' });
    try {
      await healthy(run, true);
      const response = await fetch(`http://127.0.0.1:${run.port}/api/stripe/webhook`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
      });
      assert.equal(response.status, 400);
      assert.equal((await response.json()).error, 'Missing webhook signature.');
      assert.equal((await fetch(`http://127.0.0.1:${run.port}/api/findings`)).status, 401);
      assert.equal((await fetch(`http://127.0.0.1:${run.port}/health`)).status, 200);
      assert.doesNotMatch(run.output(), /sk_live_|rk_live_|whsec_|postgresql:/);
    } finally { await cleanup(run.child); }
  });
  await t.test('malformed URL is rejected without logging its contents', async () => {
    const run = await launch({ DATABASE_URL: 'sqlite://fixture-secret@not-postgres/private' });
    const output = await exited(run);
    assert.match(output, /must be a PostgreSQL URL/);
    assert.doesNotMatch(output, /fixture-secret/);
  });
  await t.test('unreachable database fails promptly with actionable, redacted error', async () => {
    const run = await launch({ DATABASE_URL: `postgresql://hidden:fixture-password@127.0.0.1:${await freePort()}/postgres` });
    const output = await exited(run);
    assert.match(output, /PostgreSQL is unavailable.*provisioning/);
    assert.doesNotMatch(output, /fixture-password|hidden/);
  });
  await t.test('missing account tables and columns require Publish, not runtime migrations', async () => {
    for (const [alter, restore, table] of [
      ['ALTER TABLE public.vata_scan_usage RENAME TO saved_usage', 'ALTER TABLE public.saved_usage RENAME TO vata_scan_usage', 'public.vata_scan_usage'],
      ['ALTER TABLE public.vata_accounts RENAME COLUMN clerk_user_id TO saved_user', 'ALTER TABLE public.vata_accounts RENAME COLUMN saved_user TO clerk_user_id', 'public.vata_accounts'],
    ]) {
      await admin!.query(alter);
      try {
        const output = await exited(await launch());
        assert.ok(output.includes(`schema is not ready (${table})`), output);
        assert.match(output, /Publish; startup does not run migrations/);
      } finally { await admin!.query(restore); }
    }
  });
  await t.test('database permission failures are actionable', async () => {
    await admin!.query('REVOKE SELECT ON public.vata_accounts FROM startup_reader');
    try {
      assert.match(await exited(await launch()), /PostgreSQL access denied \(public.vata_accounts\)/);
    } finally { await admin!.query('GRANT SELECT ON public.vata_accounts TO startup_reader'); }
  });
  await t.test('missing bridge secret and invalid ports fail explicitly', async () => {
    assert.match(await exited(await launch({ JWT_SECRET: undefined })), /JWT_SECRET or SESSION_SECRET/);
    assert.match(await exited(await launch({ VATA_PORT: 'invalid' })), /port configuration/);
  });
  await t.test('production defaults to durable findings and cannot start without an approved namespace', async () => {
    const output = await exited(await launch({
      VATA_SQLITE_DURABILITY: undefined, VATA_FINDINGS_NAMESPACE: undefined,
    }));
    assert.match(output, /Durable findings require.*VATA_FINDINGS_NAMESPACE/);
    assert.match(output, /"reason":"startup_failed"/);
    assert.equal(output.match(/"event":"findings_storage_unavailable"/g)?.length, 1);
    assert.doesNotMatch(output, /"event":"findings_storage_ready"|"event":"findings_storage_recovered"/);
  });
  await t.test('missing Gunicorn and failed Python boot exit nonzero without a healthy public port', async () => {
    const bin = path.join(temp, 'bin');
    await mkdir(bin);
    await symlink(process.execPath, path.join(bin, 'node'));
    await symlink(tool('which', ['npm']).trim(), path.join(bin, 'npm'));
    await symlink(tool('which', ['sh']).trim(), path.join(bin, 'sh'));
    const missing = await launch({ PATH: bin });
    assert.match(await exited(missing), /Private scanner could not start.*Gunicorn/);
    const failed = await launch({ DB_FILE: path.join(temp, 'nonexistent', 'scanner.db') });
    assert.match(await exited(failed), /Private scanner stopped unexpectedly/);
    await assert.rejects(fetch(`http://127.0.0.1:${failed.port}/health`));
  });
  await t.test('HTTP success without scanner readiness times out and cleans up', async () => {
    const bin = path.join(temp, 'unready-bin');
    await mkdir(bin);
    await writeFile(path.join(bin, 'gunicorn'),
      `#!${tool('which', ['sh']).trim()}\nexec "${process.execPath}" "${path.join(root, 'tests/fixtures/unready-scanner.cjs')}"\n`,
      { mode: 0o755 });
    const run = await launch({ PATH: `${bin}:${tools.PATH}` });
    const output = await exited(run, 28000);
    assert.match(output, /Private scanner did not become ready.*DB_FILE access/);
    await assert.rejects(fetch(`http://127.0.0.1:${run.port}/health`));
    await assert.rejects(fetch(`http://127.0.0.1:${run.scannerPort}/health`));
  });
  await t.test('real root, health, private readiness, dependency loss and shutdown', async () => {
    const run = await launch();
    try {
      const response = await healthy(run);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.deepEqual(await response.json(), {
        status: 'ok', version: '3.0', dependencies: { database: 'ready', scanner: 'ready' },
      });
      const rootResponse = await fetch(`http://127.0.0.1:${run.port}/`);
      assert.equal(rootResponse.status, 200);
      assert.match(await rootResponse.text(), /<div id="root"><\/div>/);
      const scanner = await fetch(`http://127.0.0.1:${run.scannerPort}/health`);
      assert.equal(scanner.status, 200);
      assert.equal((await scanner.json()).status, 'ok');
      // Startup readiness never provisions an account or bypasses sign-in.
      assert.equal((await fetch(`http://127.0.0.1:${run.port}/api/findings`)).status, 401);
      assert.equal((await fetch(`http://127.0.0.1:${run.scannerPort}/api/findings`)).status, 401);
      assert.equal((await admin!.query('SELECT count(*) FROM public.vata_accounts')).rows[0].count, '1');

      await admin!.query('ALTER TABLE public.vata_scan_usage RENAME TO saved_usage');
      try {
        const unavailable = await fetch(`http://127.0.0.1:${run.port}/health`);
        assert.equal(unavailable.status, 503);
        const body = await unavailable.json();
        assert.equal(body.dependencies.database, 'unavailable');
        assert.doesNotMatch(JSON.stringify(body), /postgresql|startup_reader|vata_scan_usage/);
      } finally { await admin!.query('ALTER TABLE public.saved_usage RENAME TO vata_scan_usage'); }
      assert.equal((await fetch(`http://127.0.0.1:${run.port}/health`)).status, 200);
      // Gunicorn's master logs its own PID. Terminate only this fixture's scanner.
      const master = run.output().match(/\[(\d+)\] \[INFO\] Starting gunicorn/);
      assert.ok(master, run.output());
      process.kill(Number(master[1]), 'SIGTERM');
      assert.match(await exited(run), /Private scanner stopped unexpectedly/);
      await assert.rejects(fetch(`http://127.0.0.1:${run.port}/health`));
      await assert.rejects(fetch(`http://127.0.0.1:${run.scannerPort}/health`));
    } finally { await cleanup(run.child); }
    const shutdown = await launch();
    await healthy(shutdown);
    const master = shutdown.output().match(/\[(\d+)\] \[INFO\] Starting gunicorn/);
    assert.ok(master, shutdown.output());
    const gatewayPid = Number(tool('ps', ['-o', 'ppid=', '-p', master[1]]).trim());
    process.kill(gatewayPid, 'SIGTERM');
    for (let i = 0; i < 70 && shutdown.child.exitCode === null; i++) await delay(100);
    assert.equal(shutdown.child.exitCode, 0, shutdown.output());
    await assert.rejects(fetch(`http://127.0.0.1:${shutdown.scannerPort}/health`));
  });
});
