import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { mkdtemp, readFile, rm, statfs, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import { checkWorkingDisk, FindingsStorage } from '../server/findingsStorage';
import { FindingsAlerts, FindingsCapacityAlerts } from '../server/findingsAlerts';

const root = process.cwd();
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const secret = 'isolated-findings-test-signing-key-at-least-32-characters';
const tools = {
  PATH: process.env.PATH!, HOME: process.env.HOME!, LANG: 'C.UTF-8',
  PYTHONPATH: path.join(root, '.pythonlibs/lib/python3.11/site-packages'),
};
function tool(command: string, args: string[], env: NodeJS.ProcessEnv = tools) {
  return execFileSync(command, args, { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

async function freePort() {
  const socket = net.createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = (socket.address() as net.AddressInfo).port;
  await new Promise<void>(resolve => socket.close(() => resolve()));
  return port;
}

test('private SQLite snapshots survive restart and clean replacement without tenant mixing', { timeout: 120000 }, async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'vata-storage-'));
  const pgData = path.join(temp, 'postgres');
  const port = await freePort();
  const url = `postgresql://fixture_owner@127.0.0.1:${port}/postgres`;
  let postgres = false;
  let admin: pg.Client | undefined;
  const stores: FindingsStorage[] = [];
  const alerts = new Map<FindingsStorage, any[]>();
  const children = new Set<ChildProcess>();
  async function stop(child: ChildProcess) {
    try { process.kill(-child.pid!, 'SIGTERM'); } catch { return; }
    // npm can exit before its gateway child releases the writer session.
    for (let i = 0; i < 70; i++) {
      await delay(100);
      try { process.kill(-child.pid!, 0); } catch { return; }
    }
    try { process.kill(-child.pid!, 'SIGKILL'); } catch {}
  }
  t.after(async () => {
    await Promise.all([...children].map(stop));
    await Promise.all(stores.map(store => store.close()));
    await admin?.end();
    if (postgres) tool('pg_ctl', ['-D', pgData, '-m', 'immediate', '-w', 'stop']);
    await rm(temp, { recursive: true, force: true });
  });
  tool('initdb', ['-D', pgData, '-A', 'trust', '-U', 'fixture_owner', '--no-locale']);
  tool('pg_ctl', ['-D', pgData, '-l', path.join(temp, 'postgres.log'),
    '-o', `-h 127.0.0.1 -p ${port} -k ${temp}`, '-w', 'start']);
  postgres = true;
  admin = new pg.Client({ connectionString: url });
  await admin.connect();
  await admin.query(await readFile('tests/fixtures/startup-schema.sql', 'utf8'));
  await admin.query(await readFile('migrations/findings-backups.sql', 'utf8'));
  const source = path.join(temp, 'live.sqlite');
  const env = { ...tools, DB_FILE: source, JWT_SECRET: secret };
  // Full real schema + two independent owners + legacy history + WAL data.
  tool('python3', ['-c', `
import app, sqlite3
c=sqlite3.connect(app.DB_FILE)
c.execute("PRAGMA journal_mode=WAL")
for i in (1,2):
 c.execute("INSERT INTO organizations(id,name,api_key,owner_user_id) VALUES(?,?,?,?)",(-i,f'fixture-{i}',f'private-key-{i}',f'owner-{i}'))
 c.execute("INSERT INTO findings(org_id,vector_type,severity,description) VALUES(?,?,?,?)",(-i,'original','LOW',f'original-{i}'))
 c.execute("INSERT INTO scan_runs(org_id,target,status) VALUES(?,?,?)",(-i,'https://fixture.invalid','completed'))
c.execute("CREATE TABLE scan_history(id INTEGER PRIMARY KEY, org_id INTEGER, total_findings INTEGER)")
c.execute("INSERT INTO scan_history(org_id,total_findings) VALUES(-1,1)")
c.commit()
`], env);
  function store(file: string, namespace = 'fixture-live', monitor?: FindingsAlerts, capacity?: FindingsCapacityAlerts) {
    const events: any[] = [];
    const instance = new FindingsStorage(url, namespace, file,
      monitor ?? new FindingsAlerts(line => events.push(JSON.parse(line))), capacity);
    alerts.set(instance, events);
    stores.push(instance);
    return instance;
  }
  async function launch(file: string, production = false) {
    const scannerPort = await freePort();
    const gatewayPort = await freePort();
    const child = spawn(production ? 'npm' : 'python3',
      production ? ['start'] : ['tests/fixtures/findings-scanner.py'], {
        cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
        env: {
          ...tools, DATABASE_URL: url, DB_FILE: file, JWT_SECRET: secret,
          VATA_PORT: String(production ? gatewayPort : scannerPort), VATA_SCANNER_PORT: String(scannerPort),
          VATA_AUTH_BRIDGE_ENABLED: '1', VATA_SQLITE_DURABILITY: 'postgres', VATA_FINDINGS_NAMESPACE: 'fixture-live',
          CLERK_PUBLISHABLE_KEY: `pk_test_${Buffer.from('fixture.clerk.accounts.dev$').toString('base64')}`,
          CLERK_SECRET_KEY: 'sk_test_fixture_not_a_real_key', PUBLIC_APP_URL: 'https://fixture.invalid',
        },
      });
    children.add(child);
    let output = '';
    child.stdout!.on('data', data => { output += data; });
    child.stderr!.on('data', data => { output += data; });
    const healthPort = production ? gatewayPort : scannerPort;
    for (let i = 0; i < 250; i++) {
      assert.equal(child.exitCode, null, output);
      try {
        if ((await fetch(`http://127.0.0.1:${healthPort}/health`, { signal: AbortSignal.timeout(500) })).ok) {
          return { child, scannerPort, gatewayPort, output: () => output };
        }
      } catch {}
      await delay(100);
    }
    assert.fail(`Server did not become ready: ${output}`);
  }
  const seed = store(source);
  await seed.seed();
  await t.test('capacity monitor measures isolated snapshot growth and returns to normal', async () => {
    const events: any[] = [];
    const thresholds = { snapshotBytes: Number.MAX_SAFE_INTEGER, diskFreePercent: 0 };
    const capacity = new FindingsCapacityAlerts(
      thresholds,
      line => events.push(JSON.parse(line)),
    );
    const monitored = store(source, 'fixture-live', undefined, capacity);
    await monitored.open();
    const client = (monitored as any).client as pg.Client;
    const originalQuery = client.query.bind(client);
    let failCapacityProbe = false;
    (client as any).query = (query: any, values?: any) => {
      const text = typeof query === 'string' ? query : query?.text;
      if (failCapacityProbe && text.includes('SUM(octet_length(payload)')) {
        return Promise.reject(new Error('/private/path and fixture credentials'));
      }
      return originalQuery(query, values);
    };
    try {
      thresholds.snapshotBytes = 1;
      await monitored.run(async () => {});
      await monitored.run(async () => {});
      assert.equal(events.filter(event => event.event === 'findings_capacity_warning' && event.metric === 'snapshot_bytes').length, 1);
      thresholds.snapshotBytes = Number.MAX_SAFE_INTEGER;
      await monitored.run(async () => {});
      assert.ok(events.some(event => event.event === 'findings_capacity_recovered' && event.metric === 'snapshot_bytes'));

      failCapacityProbe = true;
      await monitored.run(async () => {});
      assert.equal(monitored.ready, true, 'A telemetry failure must not disable durable storage');
      assert.ok(events.some(event => event.event === 'findings_capacity_probe_failed' && event.probe === 'postgresql'));
      failCapacityProbe = false;
      await monitored.run(async () => {});
      assert.ok(events.some(event => event.event === 'findings_capacity_probe_recovered' && event.probe === 'postgresql'));

      const unavailable = (async () => { throw new Error('/private/path and fixture credentials'); }) as typeof statfs;
      const available = (async () => ({ bavail: 50n, bsize: 1n, blocks: 100n })) as typeof statfs;
      await checkWorkingDisk(source, capacity, unavailable);
      await checkWorkingDisk(source, capacity, available);
      assert.ok(events.some(event => event.event === 'findings_capacity_probe_failed' && event.probe === 'filesystem'));
      assert.ok(events.some(event => event.event === 'findings_capacity_probe_recovered' && event.probe === 'filesystem'));
      assert.doesNotMatch(JSON.stringify(events), /private.path|fixture credentials|fixture-live|postgresql:\/\//);
    } finally { await monitored.close(); }
  });
  await t.test('snapshots include committed data still held in an active SQLite WAL', async () => {
    const walSource = path.join(temp, 'active-wal.sqlite');
    await writeFile(walSource, await readFile(source), { mode: 0o600 });
    const writer = spawn('python3', ['-u', '-c', `
import sqlite3,sys,time
c=sqlite3.connect(sys.argv[1])
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA wal_autocheckpoint=0")
c.execute("INSERT INTO findings(description) VALUES('committed-in-active-wal')")
c.commit()
print("wal-ready",flush=True)
time.sleep(60)
`, walSource], { env: tools, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    children.add(writer);
    await new Promise<void>((resolve, reject) => {
      writer.stdout!.once('data', () => resolve());
      writer.once('error', reject);
      writer.once('exit', code => { if (code) reject(new Error('WAL fixture failed')); });
    });
    try {
      assert.ok((await readFile(walSource + '-wal')).length > 0);
      await store(walSource, 'fixture-wal').seed();
      const restored = path.join(temp, 'restored-wal.sqlite');
      const recovered = store(restored, 'fixture-wal');
      await recovered.open();
      assert.match(tool('python3', ['-c', `import sqlite3,sys
print(sqlite3.connect(sys.argv[1]).execute("SELECT description FROM findings WHERE description='committed-in-active-wal'").fetchone()[0])
`, restored]), /committed-in-active-wal/);
      await recovered.close();
    } finally { await stop(writer); }
  });
  await t.test('seed never overwrites, missing namespace never creates an empty DB', async () => {
    await assert.rejects(store(source).seed(), /already exists/);
    const missing = path.join(temp, 'must-not-exist.sqlite');
    const absent = store(missing, 'fixture-missing');
    await assert.rejects(absent.open(), /No approved/);
    assert.equal(alerts.get(absent)![0].reason, 'startup_failed');
    await assert.rejects(readFile(missing));
  });

  const runtime = path.join(temp, 'runtime.sqlite');
  process.env.DATABASE_URL = url;
  process.env.JWT_SECRET = secret;
  process.env.DB_FILE = runtime;
  process.env.VATA_SQLITE_DURABILITY = 'postgres';
  process.env.VATA_FINDINGS_NAMESPACE = 'fixture-live';
  const { prepareFindingsStorage } = await import('../server/findingsStorage');
  const active = (await prepareFindingsStorage())!;
  stores.push(active);
  const scanner = await launch(runtime);
  process.env.VATA_SCANNER_PORT = String(scanner.scannerPort);
  const { callScanner } = await import('../server/flaskBridge');
  const billing = { plan: 'pro', renewsAt: new Date(Date.now() + 86400000).toISOString() };
  const usage = { used: 1, month: new Date().toISOString().slice(0, 7) };
  const account = (id: number) => ({ id, clerk_user_id: `owner-${id}` });
  const call = (id: number, endpoint: string, method = 'GET', body?: any, scanning = false) =>
    callScanner(account(id), usage, scanning, endpoint, method, body);

  await t.test('single-writer lock rejects an overlapping replacement', async () => {
    await assert.rejects(store(path.join(temp, 'overlap.sqlite')).open(), /Another findings writer/);
  });
  await t.test('real gateway bridge persists findings and completed/failed scans before returning', async () => {
    assert.equal((await call(1, '/api/findings', 'POST',
      { vector_type: 'manual', severity: 'CRITICAL', description: 'new-private-finding' })).status, 201);
    const denied = await call(1, '/api/scans/mcp', 'POST', { target_url: 'https://fixture.invalid/mcp' }, true);
    assert.equal(denied.status, 403, 'Missing target authorization must not run a scan');
    const success = await call(1, '/api/scans/mcp', 'POST', { target_url: 'https://fixture.invalid/mcp', authorized: true }, true);
    assert.equal(success.status, 200);
    const failed = await call(1, '/api/scans/mcp', 'POST', { target_url: 'https://fixture.invalid/failed', authorized: true }, true);
    assert.equal(failed.status, 502);
    const findings = await call(1, '/api/findings');
    assert.equal(findings.data.findings.length, 3);
    const other = await call(2, '/api/findings');
    assert.deepEqual(other.data.findings.map((f: any) => f.description), ['original-2']);
    const runs = await call(1, '/api/scans/mcp');
    assert.deepEqual(runs.data.scans.map((s: any) => s.status), ['failed', 'completed', 'completed']);
    assert.equal((await admin!.query("SELECT count(*) FROM public.vata_findings_backups WHERE namespace='fixture-live'")).rows[0].count, '5');
  });
  await stop(scanner.child);
  await active.close();

  // Real built production startup, first preserving the old local file, then a
  // clean directory that contains no SQLite files (replacement-publish model).
  for (const [label, file] of [
    ['process restart', runtime],
    ['clean replacement build', path.join(temp, 'replacement.sqlite')],
  ]) {
    await t.test(label, async () => {
      const run = await launch(file, true);
      try {
        for (const id of [1, 2]) {
          const token = jwt.sign({
            sub: String(-id), type: 'access', fresh: false, jti: `fixture-${id}`,
            bridge: true, owner_user_id: `owner-${id}`, subscription_tier: 'pro',
            subscription_expires_at: billing.renewsAt,
          }, secret);
          const response = await fetch(`http://127.0.0.1:${run.scannerPort}/api/findings`,
            { headers: { Authorization: `Bearer ${token}` } });
          assert.equal(response.status, 200);
          const found = (await response.json()).findings;
          assert.equal(found.length, id === 1 ? 3 : 1);
          assert.ok(found.every((f: any) => f.description !== `original-${id === 1 ? 2 : 1}`));
        }
        const output = tool('python3', ['-c', `
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as c:
 assert c.execute("SELECT owner_user_id FROM organizations ORDER BY id").fetchall()==[('owner-2',),('owner-1',)]
 assert c.execute("SELECT total_findings FROM scan_history WHERE org_id=-1").fetchone()==(1,)
 assert c.execute("SELECT count(*) FROM scan_runs WHERE org_id=-1").fetchone()==(3,)
print('ownership and complete history preserved')
`, file]);
        assert.match(output, /ownership and complete history preserved/);
        assert.equal((await fetch(`http://127.0.0.1:${run.gatewayPort}/api/findings`)).status, 401);
        assert.match(run.output(), /"event":"findings_storage_ready"/);
        assert.doesNotMatch(run.output(), /"event":"findings_storage_unavailable"/);
        if (label === 'process restart') {
          // Idle loss alerts immediately, not only after a scan request.
          await admin!.query(
            'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1',
            ['vata-findings:fixture-live'],
          );
          for (let i = 0; i < 30 && !run.output().includes('"reason":"writer_lock_lost"'); i++) await delay(50);
          assert.match(run.output(), /"reason":"writer_lock_lost"/);
          const health = await fetch(`http://127.0.0.1:${run.gatewayPort}/health`);
          assert.equal(health.status, 503);
          assert.equal((await health.json()).dependencies.scanner, 'unavailable');
          assert.equal(run.output().match(/"event":"findings_storage_unavailable"/g)?.length, 1);
          assert.doesNotMatch(run.output(), /"event":"findings_storage_recovered"/);
        }
      } finally { await stop(run.child); }
    });
  }

  await t.test('dirty local data and damaged snapshots fail without overwriting either copy', async () => {
    tool('python3', ['-c', `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as c: c.execute("INSERT INTO findings(description) VALUES('unbacked-local-data')")
`, runtime]);
    await assert.rejects(store(runtime).open(), /Local SQLite differs/);
    assert.match(tool('python3', ['-c', `import sqlite3,sys
print(sqlite3.connect(sys.argv[1]).execute("SELECT description FROM findings WHERE description='unbacked-local-data'").fetchone()[0])
`, runtime]), /unbacked-local-data/);
    await admin!.query("UPDATE public.vata_findings_backups SET sha256=repeat('0',64) WHERE namespace='fixture-live'");
    const corruptPath = path.join(temp, 'corrupt.sqlite');
    await assert.rejects(store(corruptPath).open(), /checksum failed/);
    await assert.rejects(readFile(corruptPath));
    // Restore valid checksums from payload, using built-in Node hashing.
    const { createHash } = await import('node:crypto');
    for (const row of (await admin!.query('SELECT generation,payload FROM public.vata_findings_backups')).rows) {
      await admin!.query('UPDATE public.vata_findings_backups SET sha256=$1 WHERE generation=$2',
        [createHash('sha256').update(row.payload).digest('hex'), row.generation]);
    }
  });
  await t.test('backup commit failure never acknowledges a write; readiness and future writes fail closed', async () => {
    const file = path.join(temp, 'failure.sqlite');
    const events: any[] = [];
    const monitor = new FindingsAlerts(line => events.push(JSON.parse(line)));
    const failing = store(file, 'fixture-live', monitor);
    await failing.open();
    await admin!.query('ALTER TABLE public.vata_findings_backups RENAME TO saved_backups');
    try {
      await assert.rejects(failing.run(async () => {
        tool('python3', ['-c', `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as c: c.execute("INSERT INTO findings(description) VALUES('pending-recovery')")
`, file]);
        return 'success-that-must-not-be-acknowledged';
      }), /backup unavailable/);
      assert.equal(failing.ready, false);
      assert.equal(events.length, 1);
      assert.equal(events[0].reason, 'backup_failed');
    let invoked = false;
      await assert.rejects(failing.run(async () => { invoked = true; }), /backup unavailable/);
      assert.equal(invoked, false);
      assert.equal(events.length, 1);
      assert.doesNotMatch(JSON.stringify(events), /pending-recovery|fixture_owner|postgresql|private-key|owner-1|failure.sqlite/);
      assert.match(tool('python3', ['-c', `import sqlite3,sys
print(sqlite3.connect(sys.argv[1]).execute("SELECT description FROM findings WHERE description='pending-recovery'").fetchone()[0])
`, file]), /pending-recovery/);
    } finally {
      await admin!.query('ALTER TABLE public.saved_backups RENAME TO vata_findings_backups');
      await failing.close();
    }
    // Repairing PostgreSQL alone must not resume a failed writer or claim recovery.
    await assert.rejects(failing.run(async () => {}), /backup unavailable/);
    assert.equal(events.length, 1);
    const divergent = store(file, 'fixture-live', monitor);
    await assert.rejects(divergent.open(), /Local SQLite differs/);
    assert.equal(events.length, 1);
    // Model operator-approved restore to a NEW file, preserving the dirty copy.
    const recovered = store(path.join(temp, 'approved-recovery.sqlite'), 'fixture-live', monitor);
    await recovered.open();
    assert.equal(events.length, 1, 'Opening alone cannot claim verified recovery');
    await recovered.run(async () => {});
    assert.equal(events[1].event, 'findings_storage_recovered');
    await recovered.run(async () => {});
    await recovered.close();
    assert.equal(events.length, 2, 'No duplicates or shutdown alerts');
  });
  await t.test('all workspace databases and scan exports stay excluded from publishing', async () => {
    const ignore = await readFile('.replitignore', 'utf8');
    for (const pattern of ['vata.db', '**/*.db', '**/*.sqlite', 'runtime-data/', '/*findings*.json', '/*scan_results*.json']) {
      assert.ok(ignore.split('\n').includes(pattern), `Missing publishing exclusion ${pattern}`);
    }
  });
  await t.test('losing the writer-lock connection prevents further SQLite operations', async () => {
    const lost = store(path.join(temp, 'lost-connection.sqlite'));
    await lost.open();
    await admin!.query(
      'SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1',
      ['vata-findings:fixture-live'],
    );
    for (let i = 0; i < 30 && lost.ready; i++) await delay(50);
    assert.equal(lost.ready, false);
    assert.equal(alerts.get(lost)![0].reason, 'writer_lock_lost');
    let invoked = false;
    await assert.rejects(lost.run(async () => { invoked = true; }), /backup unavailable/);
    assert.equal(invoked, false);
    await lost.close();
    assert.equal(alerts.get(lost)!.length, 1);
  });
});
