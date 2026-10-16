/**
 * Operator-only offline recovery tooling. Never imported by the web service.
 * No credentials on command lines, no plaintext dump during export.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, link, lstat, mkdtemp, open, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import pg from 'pg';

const magic = Buffer.from('VATA-DR1');
const headerSize = magic.length + 12;
const tagSize = 16;

async function keyFrom(file: string) {
  const info = await lstat(file);
  if (!info.isFile() || (info.mode & 0o077) || info.size !== 32) {
    throw new Error('Encryption key must be a private regular file containing exactly 32 random bytes.');
  }
  return readFile(file);
}

function database(url: string) {
  const parsed = new URL(url);
  if (!['postgres:', 'postgresql:'].includes(parsed.protocol) || !parsed.hostname || parsed.pathname.length < 2) {
    throw new Error('A deliberate PostgreSQL connection is required.');
  }
  const supported = ['sslmode', 'sslrootcert', 'sslcert', 'sslkey', 'channel_binding'];
  for (const name of parsed.searchParams.keys()) {
    if (!supported.includes(name)) throw new Error('Unsupported PostgreSQL URL option; review operator configuration.');
  }
  return parsed;
}

function versionKey(version: string) {
  const match = /^(\d+)(?:\.(\d+))?/.exec(version);
  if (!match) throw new Error('PostgreSQL version could not be verified.');
  const major = Number(match[1]);
  const minor = Number(match[2] ?? 0);
  return major < 10 ? major * 100 + minor : major;
}

function assertCompatiblePgDump(serverVersion: string) {
  let dumpVersion = '';
  try {
    dumpVersion = execFileSync('pg_dump', ['--version'], {
      encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C.UTF-8' },
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    throw new Error('A compatible PostgreSQL pg_dump executable is required.');
  }
  const match = /PostgreSQL\)?\s+([\d.]+)/.exec(dumpVersion);
  if (!match || versionKey(match[1]) < versionKey(serverVersion)) {
    throw new Error('pg_dump must match or be newer than the selected PostgreSQL source.');
  }
}

function command(name: string, args: string[], url?: string) {
  const parsed = url ? database(url) : undefined;
  // Do not inherit ambient DATABASE_URL, PG*, app credentials, or startup hooks.
  const child = spawn(name, args, {
    env: {
      PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C.UTF-8',
      ...(parsed ? {
        PGDATABASE: decodeURIComponent(parsed.pathname.slice(1)),
        PGHOST: parsed.hostname.replace(/^\[|\]$/g, ''), PGPORT: parsed.port || '5432',
        PGUSER: decodeURIComponent(parsed.username), PGPASSWORD: decodeURIComponent(parsed.password),
        ...Object.fromEntries([...parsed.searchParams].map(([name, value]) => [`PG${name.replace(/_/g, '').toUpperCase()}`, value])),
        PGCONNECT_TIMEOUT: '10', PGAPPNAME: 'vata-offline-recovery',
      } : {}),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // pg errors can contain sensitive records/connection details. Drain, never print.
  child.stderr.resume();
  const done = new Promise<void>((resolve, reject) => {
    child.on('error', () => reject(new Error('PostgreSQL recovery tool could not start.')));
    child.on('close', code => code === 0 ? resolve() : reject(new Error('PostgreSQL recovery tool failed.')));
  });
  // Handle early rejection even while a stream pipeline is still running.
  void done.catch(() => {});
  return { child, done };
}

/** Full one-snapshot pg_dump: identity, memberships, sequences, billing, all findings generations. */
export async function exportArchive(url: string, keyFile: string, destination: string) {
  database(url);
  const source = new pg.Client({ connectionString: url, connectionTimeoutMillis: 5000 });
  try {
    await source.connect();
    await source.query('BEGIN READ ONLY');
    // Fail if the operator selected an empty/wrong/incomplete application DB.
    for (const table of ['vata_accounts', 'vata_memberships', 'vata_scan_usage',
      'vata_team_invites', 'vata_api_tokens', 'vata_scan_schedules', 'vata_findings_backups']) {
      await source.query(`SELECT * FROM public.${table} LIMIT 0`);
    }
    const version = await source.query('SHOW server_version');
    assertCompatiblePgDump(String(version.rows[0]?.server_version ?? ''));
    const ready = await source.query(`SELECT
      EXISTS(SELECT 1 FROM public.vata_accounts) AND
      EXISTS(SELECT 1 FROM public.vata_findings_backups) AS ready`);
    if (!ready.rows[0].ready) throw new Error('Recovery source has no account or findings backup records.');
    await source.query('COMMIT');
  } finally {
    await source.end().catch(() => {});
  }
  const key = await keyFrom(keyFile);
  // Same-filesystem staging permits an atomic no-clobber install.
  const temporary = await mkdtemp(path.join(path.dirname(path.resolve(destination)), '.vata-recovery-'));
  const staged = path.join(temporary, 'archive.vata-dr');
  let running: ReturnType<typeof command> | undefined;
  try {
    const header = Buffer.concat([magic, randomBytes(12)]);
    const cipher = createCipheriv('aes-256-gcm', key, header.subarray(magic.length));
    cipher.setAAD(header);
    const file = await open(staged, 'wx', 0o600);
    try { await file.writeFile(header); } finally { await file.close(); }
    running = command('pg_dump', ['--format=custom', '--no-owner', '--no-acl'], url);
    await Promise.all([
      pipeline(running.child.stdout, cipher, createWriteStream(staged, { flags: 'a', mode: 0o600 })),
      running.done,
    ]);
    const output = await open(staged, 'a');
    try {
      await output.writeFile(cipher.getAuthTag());
      await output.sync();
    } finally { await output.close(); }
    await link(staged, destination); // Refuse to overwrite any existing archive.
  } finally {
    running?.child.kill();
    key.fill(0);
    await rm(temporary, { recursive: true, force: true });
  }
}

/**
 * Restoration deliberately restricted to an empty, loopback recovery_* database.
 * This is a rehearsal tool, NOT a production schema migration/replacement path.
 */
export async function restoreIsolatedArchive(
  url: string,
  keyFile: string,
  archive: string,
  onPhase?: (phase: 'decrypt' | 'postgres-restore', elapsedMs: number) => void,
) {
  const parsed = database(url);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname)
      || !/^recovery_[a-z0-9_]+$/.test(parsed.pathname.slice(1))
      || parsed.search || parsed.hash) {
    throw new Error('Restore requires an empty loopback recovery_* database without URL options.');
  }
  const key = await keyFrom(keyFile);
  const temporary = await mkdtemp(path.join(tmpdir(), 'vata-recovery-'));
  const dump = path.join(temporary, 'database.dump');
  const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 5000 });
  let running: ReturnType<typeof command> | undefined;
  try {
    await chmod(temporary, 0o700);
    await client.connect();
    const objects = await client.query(`
      SELECT 1 FROM pg_namespace
      WHERE nspname !~ '^pg_' AND nspname NOT IN ('public','information_schema')
      UNION ALL
      SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public'
      UNION ALL
      SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
      UNION ALL
      SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public'
      LIMIT 1`);
    if (objects.rowCount) throw new Error('Isolated restore target is not empty; nothing was replaced.');
    const input = await open(archive, 'r');
    let size: number;
    const header = Buffer.alloc(headerSize);
    const tag = Buffer.alloc(tagSize);
    try {
      size = (await input.stat()).size;
      if (size <= headerSize + tagSize) throw new Error('Invalid encrypted archive.');
      await input.read(header, 0, headerSize, 0);
      await input.read(tag, 0, tagSize, size - tagSize);
    } finally { await input.close(); }
    if (!header.subarray(0, magic.length).equals(magic)) throw new Error('Unknown recovery archive version.');
    const decipher = createDecipheriv('aes-256-gcm', key, header.subarray(magic.length));
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    // Authenticate the ENTIRE archive before pg_restore can execute any SQL.
    const decryptStarted = performance.now();
    await pipeline(
      createReadStream(archive, { start: headerSize, end: size - tagSize - 1 }),
      decipher, createWriteStream(dump, { flags: 'wx', mode: 0o600 }),
    );
    onPhase?.('decrypt', performance.now() - decryptStarted);
    running = command('pg_restore', [
      '--dbname', parsed.pathname.slice(1), '--no-owner', '--no-acl',
      '--exit-on-error', '--single-transaction', dump,
    ], url);
    running.child.stdout.resume();
    const restoreStarted = performance.now();
    await running.done;
    onPhase?.('postgres-restore', performance.now() - restoreStarted);
  } finally {
    running?.child.kill();
    await client.end().catch(() => {});
    key.fill(0);
    await rm(temporary, { recursive: true, force: true });
  }
}

async function main() {
  const [operation, approval, file, ...extra] = process.argv.slice(2);
  const key = process.env.VATA_RECOVERY_KEY_FILE;
  if (!key || !file || extra.length) throw new Error('Explicit operator configuration is required.');
  if (operation === 'export' && approval === '--approve-sensitive-export' && process.env.VATA_RECOVERY_SOURCE_URL) {
    await exportArchive(process.env.VATA_RECOVERY_SOURCE_URL, key, file);
    console.log('Encrypted archive created locally. Not an independent backup until verified off-project.');
  } else if (operation === 'restore-isolated' && approval === '--approve-isolated-restore' && process.env.VATA_RECOVERY_TARGET_URL) {
    await restoreIsolatedArchive(process.env.VATA_RECOVERY_TARGET_URL, key, file);
    console.log('Isolated database restored. Verify ownership and authenticated tenant isolation before accepting recovery.');
  } else {
    throw new Error('Explicit export or isolated-restore approval is required.');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(() => {
    console.error('Offline recovery failed. No production restore is supported. Check approval, private key, archive integrity, PostgreSQL tools and isolated target; see docs/independent-recovery.md.');
    process.exitCode = 1;
  });
}
