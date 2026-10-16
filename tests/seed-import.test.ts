import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import net from 'node:net';
import { createHash } from 'node:crypto';
import pg from 'pg';

const environment = { PATH: process.env.PATH!, HOME: process.env.HOME!, LANG: 'C.UTF-8' };
const tool = (command: string, args: string[]) =>
  execFileSync(command, args, { env: environment, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

test('operator import validates round-trip, repeat safety, ownership and writer exclusion', { timeout: 45000 }, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'vata-import-test-'));
  const data = path.join(directory, 'pg');
  const socket = net.createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = (socket.address() as net.AddressInfo).port;
  await new Promise<void>(resolve => socket.close(() => resolve()));
  let running = false;
  let client: pg.Client | undefined;
  let locker: pg.Client | undefined;
  t.after(async () => {
    await locker?.end().catch(() => {});
    await client?.end().catch(() => {});
    if (running) tool('pg_ctl', ['-D', data, '-m', 'immediate', '-w', 'stop']);
    await rm(directory, { recursive: true, force: true });
  });
  tool('initdb', ['-D', data, '-A', 'trust', '-U', 'fixture_owner', '--no-locale']);
  tool('pg_ctl', ['-D', data, '-l', path.join(directory, 'postgres.log'), '-o',
    `-h 127.0.0.1 -p ${port} -k ${directory}`, '-w', 'start']);
  running = true;
  const connectionString = `postgresql://fixture_owner@127.0.0.1:${port}/postgres`;
  client = new pg.Client({ connectionString });
  await client.connect();
  await client.query(await readFile('migrations/findings-backups.sql', 'utf8'));
  await client.query(`CREATE TABLE public.vata_accounts(id integer PRIMARY KEY, clerk_user_id text);
    INSERT INTO public.vata_accounts VALUES(1,'synthetic-owner')`);
  const sql = await readFile('generated-artifacts/production-findings-seed.sql', 'utf8');
  await client.query(sql);
  const first = await client.query("SELECT sha256,payload FROM public.vata_findings_backups WHERE namespace='production-findings'");
  assert.equal(first.rowCount, 1);
  const payload = first.rows[0].payload as Buffer;
  assert.equal(createHash('sha256').update(payload).digest('hex'), first.rows[0].sha256);
  const file = path.join(directory, 'restored.sqlite');
  await writeFile(file, payload);
  tool('python3', ['-c', `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as c:
 assert c.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
 for t in ("organizations","findings","scan_runs","compliance_reports"):
  assert c.execute("SELECT COUNT(*) FROM "+t).fetchone()[0]==0
 c.execute("INSERT INTO findings(org_id,severity,description) VALUES(1,'critical','Synthetic existing finding')")
`, file]);
  // Even a later, nonempty snapshot must survive an accidental repeat import.
  const nonempty = await readFile(file);
  const nonemptySha = createHash('sha256').update(nonempty).digest('hex');
  await client.query("UPDATE public.vata_findings_backups SET payload=$1,sha256=$2 WHERE namespace='production-findings'", [nonempty, nonemptySha]);
  await client.query(sql);
  const repeated = await client.query("SELECT sha256,payload FROM public.vata_findings_backups WHERE namespace='production-findings'");
  assert.equal(repeated.rowCount, 1);
  assert.equal(repeated.rows[0].sha256, nonemptySha);
  assert.deepEqual(repeated.rows[0].payload, nonempty);
  assert.deepEqual((await client.query('SELECT * FROM public.vata_accounts')).rows, [{ id: 1, clerk_user_id: 'synthetic-owner' }]);
  locker = new pg.Client({ connectionString });
  await locker.connect();
  await locker.query("SELECT pg_advisory_lock(hashtextextended('vata-findings:production-findings',0))");
  await assert.rejects(client.query(sql), (error: any) => error.code === '55P03');
  await client.query('ROLLBACK');
  assert.deepEqual((await client.query("SELECT payload FROM public.vata_findings_backups WHERE namespace='production-findings'")).rows[0].payload, nonempty);
});
