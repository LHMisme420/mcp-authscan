import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { mkdtemp, readFile, rm, mkdir, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
import pg from 'pg';
import { createHash } from 'node:crypto';

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
function tool(command: string, args: string[], env: NodeJS.ProcessEnv = tools) {
  return execFileSync(command, args, { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
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
  async function healthy(run: Awaited<ReturnType<typeof launch>>) {
    for (let i = 0; i < 250; i++) {
      assert.equal(run.child.exitCode, null, run.output());
      try {
        const response = await fetch(`http://127.0.0.1:${run.port}/health`, { signal: AbortSignal.timeout(500) });
        if (response.status === 200) {
          for (const paymentPath of ['/api/checkout', '/api/test-checkout', '/api/test-checkout/webhook', '/api/billing/status', '/api/stripe/webhook']) {
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
  async function warming(run: Awaited<ReturnType<typeof launch>>) {
    for (let i = 0; i < 120; i++) {
      assert.equal(run.child.exitCode, null, run.output());
      try {
        const response = await fetch(`http://127.0.0.1:${run.port}/`, { signal: AbortSignal.timeout(500) });
        if (response.status === 200) {
          assert.match(await response.text(), /<div id="root"><\/div>/);
          const health = await fetch(`http://127.0.0.1:${run.port}/health`);
          assert.equal(health.status, 503);
          assert.equal((await health.json()).dependencies.scanner, 'unavailable');
          return;
        }
      } catch {}
      await delay(100);
    }
    assert.fail(`Frontend did not become live while waiting for the writer:\n${run.output()}`);
  }
  async function blockedApis(run: Awaited<ReturnType<typeof launch>>) {
    for (const [method, endpoint] of [
      ['GET', '/api/findings'], ['GET', '/api/reports/pdf'],
      ['POST', '/api/findings'], ['POST', '/api/scans/mcp'],
      ['POST', '/api/scan'], ['POST', '/api/schedule-scan'],
    ]) {
      const response = await fetch(`http://127.0.0.1:${run.port}${endpoint}`, {
        method, ...(method === 'POST' ? {
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ target_url: 'https://fixture.invalid', authorized: true }),
        } : {}),
      });
      assert.equal(response.status, 503, `${method} ${endpoint}`);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('retry-after'), '2');
      assert.equal((await response.json()).code, 'WRITER_NOT_READY');
    }
  }
  await t.test('missing URL fails without local PostgreSQL fallback or credential output', async () => {
    const run = await launch({ DATABASE_URL: undefined });
    assert.match(await exited(run), /DATABASE_URL is missing.*Publish/);
    await assert.rejects(fetch(`http://127.0.0.1:${run.port}/health`));
  });
  await t.test('stale live setup flags cannot reactivate payment routes or block HTTP readiness', async () => {
    const run = await launch({ VATA_BILLING_MODE: 'live', VATA_PREPARE_LIVE_BILLING: '1' });
    try {
      await healthy(run);
      const response = await fetch(`http://127.0.0.1:${run.port}/api/stripe/webhook`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
      });
      assert.equal(response.status, 410);
      assert.equal((await response.json()).error, 'Payments are not enabled.');
      assert.equal((await fetch(`http://127.0.0.1:${run.port}/api/findings`)).status, 401);
      assert.equal((await fetch(`http://127.0.0.1:${run.port}/health`)).status, 200);
      assert.doesNotMatch(run.output(), /sk_live_|rk_live_|whsec_|postgresql:/);
      assert.doesNotMatch(run.output(), /Stripe .*synchronization|Optional live billing setup|billing unavailable/);
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

  // Keep the original readiness-only role read-only. Fresh initialization needs
  // a separate, least-privileged fixture writer, not a weakened readiness guard.
  await admin!.query(`CREATE ROLE startup_findings_writer LOGIN;
    GRANT CONNECT ON DATABASE postgres TO startup_findings_writer;
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO startup_findings_writer;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO startup_findings_writer`);
  const freshNamespace = 'fixture-fresh-start';
  const fresh = (namespace = freshNamespace) => ({
    DATABASE_URL: `postgresql://startup_findings_writer@127.0.0.1:${pgPort}/postgres`,
    VATA_SQLITE_DURABILITY: 'postgres', VATA_FINDINGS_NAMESPACE: namespace,
    VATA_FINDINGS_INITIALIZE_EMPTY: namespace,
  });
  await t.test('fresh approval cannot create missing PostgreSQL schema at startup', async () => {
    const run = await launch(fresh());
    assert.match(await exited(run), /Findings backup unavailable/);
    const schema = await admin!.query("SELECT to_regclass('public.vata_findings_backups') AS table_name");
    assert.equal(schema.rows[0].table_name, null);
  });

  // Only the isolated fixture administrator applies schema. Production startup
  // must rely on the reviewed Publish schema process instead.
  await admin!.query(await readFile('migrations/findings-backups.sql', 'utf8'));
  await admin!.query(await readFile('migrations/findings-fresh-start.sql', 'utf8'));
  await admin!.query(`GRANT SELECT,INSERT,DELETE ON public.vata_findings_backups TO startup_findings_writer;
    GRANT SELECT,INSERT ON public.vata_findings_initializations TO startup_findings_writer;
    GRANT USAGE ON SEQUENCE public.vata_findings_backups_generation_seq TO startup_findings_writer`);

  await t.test('missing snapshots fail even with stale fresh-initialization flags', async () => {
    const absent = await launch({ ...fresh(), VATA_FINDINGS_INITIALIZE_EMPTY: undefined });
    assert.match(await exited(absent), /No approved findings backup exists/);
    const mismatched = await launch({ ...fresh(), VATA_FINDINGS_INITIALIZE_EMPTY: 'different-namespace' });
    assert.match(await exited(mismatched), /No approved findings backup exists/);
    assert.equal((await admin!.query('SELECT COUNT(*) FROM public.vata_findings_backups')).rows[0].count, '0');
  });

  await t.test('missing remote snapshot never overwrites existing local data or sidecars', async () => {
    for (const suffix of ['', '-wal', '-shm', '-journal']) {
      const file = path.join(temp, `existing-${suffix || 'main'}.sqlite`);
      await writeFile(file + suffix, 'synthetic-do-not-replace');
      const run = await launch({ ...fresh(), DB_FILE: file });
      assert.match(await exited(run), /No approved findings backup exists/);
      assert.equal(await readFile(file + suffix, 'utf8'), 'synthetic-do-not-replace');
    }
    assert.equal((await admin!.query('SELECT COUNT(*) FROM public.vata_findings_backups')).rows[0].count, '0');
  });

  await t.test('operator seed command commits once and refuses to overwrite the namespace', async () => {
    const source = path.join(temp, 'operator-seed.sqlite');
    tool('python3', ['-c', `import os,sys
os.environ['DB_FILE']=sys.argv[1]
os.environ['JWT_SECRET']='synthetic-schema-fixture-signing-key'
import app`, source]);
    const env = { ...tools, DATABASE_URL: fresh().DATABASE_URL, DB_FILE: source, VATA_FINDINGS_NAMESPACE: freshNamespace };
    const output = tool('npm', ['run', 'findings:seed', '--', '--approve-live-snapshot'], env);
    assert.match(output, /Initial private findings snapshot committed/);
    assert.equal((await admin!.query('SELECT COUNT(*) FROM public.vata_findings_backups')).rows[0].count, '1');
    assert.throws(() => tool('npm', ['run', 'findings:seed', '--', '--approve-live-snapshot'], env));
    assert.equal((await admin!.query('SELECT COUNT(*) FROM public.vata_findings_backups')).rows[0].count, '1');
  });

  await t.test('manually seeded production start, writer exclusion and replacement restore succeed', async () => {
    const file = path.join(temp, 'fresh-working.sqlite');
    const first = await launch({ ...fresh(), DB_FILE: file });
    let originalSha = '';
    try {
      await healthy(first);
      assert.doesNotMatch(first.output(), /initialized with an empty snapshot/);
      assert.doesNotMatch(first.output(), /LOCAL-ONLY/);
      const count = tool('python3', ['-c',
        'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print([c.execute("SELECT COUNT(*) FROM "+t).fetchone()[0] for t in ("organizations","findings","scan_runs")])', file]);
      assert.equal(count.trim(), '[0, 0, 0]');
      const snapshot = await admin!.query('SELECT sha256 FROM public.vata_findings_backups WHERE namespace=$1', [freshNamespace]);
      assert.equal(snapshot.rowCount, 1);
      originalSha = snapshot.rows[0].sha256;
      assert.equal((await admin!.query('SELECT COUNT(*) FROM public.vata_findings_initializations WHERE namespace=$1', [freshNamespace])).rows[0].count, '0');
      const competing = await launch({
        ...fresh(), VATA_FINDINGS_LOCK_TIMEOUT_MS: '2500', VATA_FINDINGS_LOCK_RETRY_MS: '100',
      });
      await warming(competing);
      await blockedApis(competing);
      await assert.rejects(fetch(`http://127.0.0.1:${competing.scannerPort}/health`));
      const output = await exited(competing);
      assert.match(output, /writer lock acquisition timed out.*Another findings writer is active/);
      assert.match(output, /"event":"findings_writer_waiting"/);
      assert.doesNotMatch(output, /"event":"findings_storage_ready"|"event":"findings_storage_recovered"|Starting gunicorn/);
      assert.equal((await fetch(`http://127.0.0.1:${first.port}/health`)).status, 200);
    } finally { await cleanup(first.child); }
    const replacement = await launch({ ...fresh(), DB_FILE: path.join(temp, 'replacement-working.sqlite') });
    try {
      await healthy(replacement);
      assert.doesNotMatch(replacement.output(), /initialized with an empty snapshot/);
      const restored = await admin!.query('SELECT sha256 FROM public.vata_findings_backups WHERE namespace=$1', [freshNamespace]);
      assert.deepEqual(restored.rows, [{ sha256: originalSha }]);
    } finally { await cleanup(replacement.child); }
  });

  await t.test('existing nonempty and corrupted snapshots are never replaced by a fresh seed', async () => {
    const source = path.join(temp, 'existing-source.sqlite');
    tool('python3', ['-c', `import os,sys,sqlite3
os.environ['DB_FILE']=sys.argv[1]
os.environ['JWT_SECRET']='synthetic-schema-fixture-signing-key'
import app
with sqlite3.connect(app.DB_FILE) as c:
 c.execute("INSERT INTO organizations(id,name,owner_user_id) VALUES(1,'Synthetic workspace','synthetic-owner')")
 c.execute("INSERT INTO findings(org_id,severity,description) VALUES(1,'critical','Synthetic existing finding')")
`, source]);
    const payload = await readFile(source);
    const checksum = createHash('sha256').update(payload).digest('hex');
    for (const corrupt of [false, true]) {
      const namespace = corrupt ? 'fixture-corrupt' : 'fixture-existing';
      const sha256 = corrupt ? '0'.repeat(64) : checksum;
      await admin!.query('INSERT INTO public.vata_findings_backups(namespace,sha256,payload) VALUES($1,$2,$3)', [namespace, sha256, payload]);
      const destination = path.join(temp, `${namespace}.sqlite`);
      const run = await launch({ ...fresh(namespace), DB_FILE: destination });
      try {
        if (corrupt) assert.match(await exited(run), /Stored findings backup checksum failed/);
        else {
          await healthy(run);
          assert.equal(tool('python3', ['-c', 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("SELECT COUNT(*) FROM findings").fetchone()[0])', destination]).trim(), '1');
        }
        assert.doesNotMatch(run.output(), /initialized with an empty snapshot/);
        const unchanged = await admin!.query('SELECT sha256,payload FROM public.vata_findings_backups WHERE namespace=$1', [namespace]);
        assert.equal(unchanged.rowCount, 1);
        assert.equal(unchanged.rows[0].sha256, sha256);
        assert.deepEqual(unchanged.rows[0].payload, payload);
      } finally { await cleanup(run.child); }
    }
  });

  await t.test('overlapping frontend promotion hands off one writer, preserves rows, and fails closed after session loss', async () => {
    const namespace = 'fixture-existing';
    const old = await launch({ ...fresh(namespace), DB_FILE: path.join(temp, 'handoff-old.sqlite') });
    let replacement: Awaited<ReturnType<typeof launch>> | undefined;
    try {
      await healthy(old);
      const file = path.join(temp, 'handoff-new.sqlite');
      replacement = await launch({
        ...fresh(namespace), DB_FILE: file,
        VATA_FINDINGS_LOCK_TIMEOUT_MS: '20000', VATA_FINDINGS_LOCK_RETRY_MS: '100',
      });
      await warming(replacement);
      await blockedApis(replacement);
      await assert.rejects(readFile(file), { code: 'ENOENT' });
      await assert.rejects(fetch(`http://127.0.0.1:${replacement.scannerPort}/health`));
      assert.doesNotMatch(replacement.output(), /"event":"findings_storage_ready"|Starting gunicorn/);
      assert.equal((await admin!.query('SELECT count(*) FROM public.vata_accounts')).rows[0].count, '1');
      const locks = await admin!.query(`SELECT count(*) FROM pg_locks l
        WHERE l.locktype='advisory' AND l.granted AND l.objsubid=1
        AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())
        AND l.classid=((hashtextextended('vata-findings:' || $1,0)>>32)&4294967295)::oid
        AND l.objid=(hashtextextended('vata-findings:' || $1,0)&4294967295)::oid`, [namespace]);
      assert.equal(locks.rows[0].count, '1');

      // Emulate the platform draining the old revision only after new / is live.
      await cleanup(old.child);
      await healthy(replacement);
      assert.match(replacement.output(), /"event":"findings_writer_waiting"/);
      assert.equal(replacement.output().match(/"event":"findings_storage_ready"/g)?.length, 1);
      const preserved = tool('python3', ['-c', `import sqlite3,sys,json
c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True)
print(json.dumps([c.execute("SELECT owner_user_id FROM organizations").fetchall(),c.execute("SELECT description FROM findings").fetchall()]))
`, file]);
      assert.deepEqual(JSON.parse(preserved), [[['synthetic-owner']], [['Synthetic existing finding']]]);
      assert.equal((await fetch(`http://127.0.0.1:${replacement.port}/api/findings`)).status, 401);

      // Terminate only this isolated fixture's lock session, never a live DB.
      const ended = await admin!.query(
        'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1',
        [`vata-findings:${namespace}`],
      );
      assert.equal(ended.rowCount, 1);
      for (let i = 0; i < 30 && !replacement.output().includes('"reason":"writer_lock_lost"'); i++) await delay(50);
      const unavailable = await fetch(`http://127.0.0.1:${replacement.port}/health`);
      assert.equal(unavailable.status, 503);
      await blockedApis(replacement);
      assert.equal((await fetch(`http://127.0.0.1:${replacement.port}/`)).status, 200);
      assert.match(replacement.output(), /"reason":"writer_lock_lost"/);
      assert.equal(replacement.output().match(/"event":"findings_storage_ready"/g)?.length, 1);
      assert.doesNotMatch(replacement.output(), /LOCAL-ONLY|"event":"findings_storage_recovered"/);
    } finally {
      await cleanup(old.child);
      if (replacement) await cleanup(replacement.child);
    }
  });

  await t.test('SIGTERM cancels a waiting replacement without starting its scanner or stealing the lock', async () => {
    const namespace = 'fixture-existing';
    await admin!.query("SELECT pg_advisory_lock(hashtextextended('vata-findings:' || $1,0))", [namespace]);
    const file = path.join(temp, 'cancelled-wait.sqlite');
    const run = await launch({ ...fresh(namespace), DB_FILE: file });
    try {
      await warming(run);
      await blockedApis(run);
      await cleanup(run.child);
      await assert.rejects(fetch(`http://127.0.0.1:${run.port}/health`));
      await assert.rejects(readFile(file), { code: 'ENOENT' });
      assert.doesNotMatch(run.output(), /Starting gunicorn|findings_storage_ready|findings_storage_unavailable/);
      const sessions = await admin!.query('SELECT count(*) FROM pg_stat_activity WHERE application_name=$1', [`vata-findings:${namespace}`]);
      assert.equal(sessions.rows[0].count, '0');
    } finally {
      await cleanup(run.child);
      await admin!.query("SELECT pg_advisory_unlock(hashtextextended('vata-findings:' || $1,0))", [namespace]);
    }
  });

  await t.test('lost snapshots cannot be silently reinitialized after first bootstrap', async () => {
    await admin!.query('DELETE FROM public.vata_findings_backups WHERE namespace=$1', [freshNamespace]);
    const run = await launch(fresh());
    assert.match(await exited(run), /No approved findings backup exists/);
    assert.equal((await admin!.query('SELECT COUNT(*) FROM public.vata_findings_backups WHERE namespace=$1', [freshNamespace])).rows[0].count, '0');
    assert.equal((await admin!.query('SELECT COUNT(*) FROM public.vata_findings_initializations WHERE namespace=$1', [freshNamespace])).rows[0].count, '0');
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
    const run = await launch({ PATH: `${bin}:${tools.PATH}`, VATA_SCANNER_STARTUP_TIMEOUT_MS: '800' });
    const output = await exited(run);
    assert.match(output, /Private scanner did not become ready.*DB_FILE access/);
    await assert.rejects(fetch(`http://127.0.0.1:${run.port}/health`));
    await assert.rejects(fetch(`http://127.0.0.1:${run.scannerPort}/health`));
  });
  await t.test('scanner boot longer than the former 20-second deadline keeps liveness up and becomes ready', async () => {
    const bin = path.join(temp, 'slow-scanner-bin');
    await mkdir(bin);
    await writeFile(path.join(bin, 'gunicorn'),
      `#!${tool('which', ['sh']).trim()}\nexec "${process.execPath}" "${path.join(root, 'tests/fixtures/unready-scanner.cjs')}"\n`,
      { mode: 0o755 });
    const run = await launch({
      PATH: `${bin}:${tools.PATH}`, VATA_FIXTURE_SCANNER_READY_AFTER_MS: '21000',
    });
    try {
      await warming(run);
      await blockedApis(run);
      await healthy(run);
      assert.doesNotMatch(run.output(), /Private scanner did not become ready/);
      assert.equal((await fetch(`http://127.0.0.1:${run.port}/`)).status, 200);
    } finally { await cleanup(run.child); }
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
