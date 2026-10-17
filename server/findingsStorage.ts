import pg from 'pg';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, link, mkdtemp, readFile, rm, stat, statfs, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import {
  DEFAULT_FINDINGS_CAPACITY_THRESHOLDS, FindingsCapacityAlerts, findingsAlerts,
  readFindingsCapacityThresholds, type FindingsAlerts,
} from './findingsAlerts';

const execute = promisify(execFile);
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const helper = path.resolve('scripts/sqlite-snapshot.py');
const failure = () => new Error('Findings backup unavailable. Writes are paused; preserve DB_FILE and follow docs/findings-storage.md.');

export class FindingsWriterBusyError extends Error {
  constructor() {
    super('Another findings writer is active. Stop the previous instance before replacement; never run two SQLite writers.');
    this.name = 'FindingsWriterBusyError';
  }
}

export function validateFindingsConfiguration() {
  const mode = process.env.VATA_SQLITE_DURABILITY ?? (process.env.NODE_ENV === 'production' ? 'postgres' : 'local');
  if (mode !== 'postgres' && mode !== 'local') throw new Error('VATA_SQLITE_DURABILITY must be postgres or local.');
  if (mode === 'postgres' && (!process.env.VATA_FINDINGS_NAMESPACE || !process.env.DATABASE_URL || !process.env.DB_FILE)) {
    throw new Error('Durable findings require DATABASE_URL, an explicit DB_FILE and VATA_FINDINGS_NAMESPACE; see docs/findings-storage.md.');
  }
  if (mode === 'postgres' && !/^[a-z][a-z0-9_-]{2,63}$/.test(process.env.VATA_FINDINGS_NAMESPACE!)) {
    throw new Error('Set an explicit, environment-specific VATA_FINDINGS_NAMESPACE (3-64 lowercase characters).');
  }
  readFindingsCapacityThresholds();
  return mode;
}

async function exists(file: string) {
  try { await stat(file); return true; }
  catch (error: any) { if (error.code === 'ENOENT') return false; throw error; }
}
async function sqlite(operation: string, source: string, destination?: string) {
  const result = await execute('python3', [helper, operation, source, ...(destination ? [destination] : [])],
    { timeout: 60000, maxBuffer: 1024 });
  return result.stdout.trim();
}

export async function checkWorkingDisk(
  dbFile: string,
  capacityAlerts: FindingsCapacityAlerts,
  statfsProbe: typeof statfs = statfs,
) {
  const directories = new Set([path.dirname(path.resolve(dbFile)), tmpdir()]);
  let lowestFreePercent = Infinity;
  let lowestFreeBytes = 0;
  let lowestTotalBytes = 0;
  let probeFailed = false;
  for (const directory of directories) {
    try {
      const filesystem = await statfsProbe(directory, { bigint: true });
      const freeBytes = Number(filesystem.bavail * filesystem.bsize);
      const totalBytes = Number(filesystem.blocks * filesystem.bsize);
      const freePercent = totalBytes > 0 ? freeBytes / totalBytes : Infinity;
      if (freePercent < lowestFreePercent) {
        lowestFreePercent = freePercent;
        lowestFreeBytes = freeBytes;
        lowestTotalBytes = totalBytes;
      }
    } catch {
      // Capacity telemetry must not block scans or persistence when statfs is unavailable.
      probeFailed = true;
    }
  }
  if (probeFailed) capacityAlerts.probeFailed('filesystem');
  else capacityAlerts.probeRecovered('filesystem');
  if (Number.isFinite(lowestFreePercent)) capacityAlerts.diskSpace(lowestFreeBytes, lowestTotalBytes);
}

/** One live writer per namespace. A dedicated session owns the advisory lock. */
export class FindingsStorage {
  private client: pg.Client;
  private tail: Promise<unknown> = Promise.resolve();
  private healthy = false;
  private closed = false;
  private sessionLost = false;
  private fingerprint: string | undefined;
  constructor(
    readonly databaseUrl: string, readonly namespace: string, readonly dbFile: string,
    private readonly alerts: FindingsAlerts = findingsAlerts,
    private readonly capacityAlerts: FindingsCapacityAlerts = new FindingsCapacityAlerts(DEFAULT_FINDINGS_CAPACITY_THRESHOLDS),
  ) {
    if (!/^[a-z][a-z0-9_-]{2,63}$/.test(namespace)) throw new Error('Set an explicit, environment-specific VATA_FINDINGS_NAMESPACE (3-64 lowercase characters).');
    this.client = new pg.Client({
      connectionString: databaseUrl, connectionTimeoutMillis: 5000,
      query_timeout: 15000, statement_timeout: 15000, keepAlive: true,
      application_name: `vata-findings:${namespace}`,
    });
    const lost = () => {
      if (this.closed) return;
      this.sessionLost = true;
      this.healthy = false;
      this.alerts.fail('writer_lock_lost');
    };
    this.client.on('error', lost);
    this.client.on('end', lost);
  }
  get ready() { return this.healthy && !this.closed; }

  private async connect() {
    await this.client.connect();
    const lock = await this.client.query(
      "SELECT pg_try_advisory_lock(hashtextextended('vata-findings:' || $1, 0)) AS acquired", [this.namespace],
    );
    if (!lock.rows[0].acquired) throw new FindingsWriterBusyError();
    await this.client.query('SELECT namespace,generation,sha256,payload FROM public.vata_findings_backups LIMIT 0');
  }

  async open() {
    try {
      await this.connect();
      const result = await this.client.query(
        'SELECT sha256,payload FROM public.vata_findings_backups WHERE namespace=$1 ORDER BY generation DESC LIMIT 1', [this.namespace],
      );
      const snapshot = result.rows[0];
      if (!snapshot) throw new Error('No approved findings backup exists for this namespace. Seed from the LIVE SQLite database before replacing the deployment; see docs/findings-storage.md.');
      const temporary = await mkdtemp(path.join(path.dirname(path.resolve(this.dbFile)), '.vata-restore-'));
      try {
        const restored = path.join(temporary, 'restore.sqlite');
        if (digest(snapshot.payload) !== snapshot.sha256) throw new Error('Stored findings backup checksum failed. Preserve all copies and follow the recovery runbook.');
        await writeFile(restored, snapshot.payload, { mode: 0o600 });
        const fingerprint = await sqlite('check', restored);
        if (await exists(this.dbFile)) {
          if (await sqlite('check', this.dbFile) !== fingerprint) {
            throw new Error('Local SQLite differs from its durable backup. Neither copy was replaced. Preserve DB_FILE and use the recovery runbook.');
          }
          await chmod(this.dbFile, 0o600);
        } else {
          // Never attach a replacement main file to leftover WAL/journal files.
          for (const suffix of ['-wal', '-shm', '-journal']) {
            if (await exists(this.dbFile + suffix)) throw new Error('SQLite sidecar files need manual recovery before restore.');
          }
          // Atomic no-clobber install, on the same filesystem.
          await link(restored, this.dbFile);
        }
        this.fingerprint = fingerprint;
      } finally { await rm(temporary, { recursive: true, force: true }); }
      if (this.sessionLost) throw failure();
      this.healthy = true;
      await this.checkSnapshotCapacity();
      await checkWorkingDisk(this.dbFile, this.capacityAlerts);
    } catch (error) {
      if (!(error instanceof FindingsWriterBusyError)) this.alerts.fail('startup_failed');
      await this.close();
      // Never expose pg errors or Python stderr, which may contain private paths.
      if (error instanceof Error && /^(Another findings|No approved|Stored findings|Local SQLite|SQLite sidecar|Fresh findings)/.test(error.message)) throw error;
      throw failure();
    }
  }

  private async save() {
    const temporary = await mkdtemp(path.join(tmpdir(), 'vata-snapshot-'));
    try {
      const file = path.join(temporary, 'snapshot.sqlite');
      const fingerprint = await sqlite('snapshot', this.dbFile, file);
      if (fingerprint === this.fingerprint) return;
      const bytes = await readFile(file);
      await this.client.query('BEGIN');
      try {
        await this.client.query(
          'INSERT INTO public.vata_findings_backups(namespace,sha256,payload) VALUES($1,$2,$3)',
          [this.namespace, digest(bytes), bytes],
        );
        // Keep five complete generations, atomically with the new snapshot.
        await this.client.query(
          `DELETE FROM public.vata_findings_backups WHERE namespace=$1 AND generation NOT IN
           (SELECT generation FROM public.vata_findings_backups WHERE namespace=$1 ORDER BY generation DESC LIMIT 5)`,
          [this.namespace],
        );
        await this.client.query('COMMIT');
        this.fingerprint = fingerprint;
      } catch (error) {
        await this.client.query('ROLLBACK').catch(() => {});
        throw error;
      }
    } finally { await rm(temporary, { recursive: true, force: true }); }
  }

  private async checkSnapshotCapacity() {
    try {
      // Aggregate only stored byte lengths; snapshot payloads never leave PostgreSQL.
      const result = await this.client.query(
        `SELECT COALESCE(SUM(octet_length(payload)::bigint),0)::text AS bytes
         FROM public.vata_findings_backups WHERE namespace=$1`,
        [this.namespace],
      );
      this.capacityAlerts.snapshotUsage(Number(result.rows[0].bytes));
      this.capacityAlerts.probeRecovered('postgresql');
    } catch {
      // A failed telemetry query must not turn a committed snapshot into a failed scan.
      this.capacityAlerts.probeFailed('postgresql');
    }
  }

  /** Called only by the explicit operator seed command; never during startup. */
  async seed() {
    try {
      await this.connect();
      const result = await this.client.query('SELECT 1 FROM public.vata_findings_backups WHERE namespace=$1 LIMIT 1', [this.namespace]);
      if (result.rowCount) throw new Error('A backup already exists; seed refuses to overwrite it.');
      await this.save();
    } finally { await this.close(); }
  }

  async run<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.tail.then(async () => {
      if (!this.ready) {
        this.alerts.remind();
        throw failure();
      }
      await checkWorkingDisk(this.dbFile, this.capacityAlerts);
      try {
        // Detect lost writer-lock sessions BEFORE allowing any SQLite mutation.
        await this.client.query('SELECT 1');
      } catch {
        this.healthy = false;
        this.alerts.fail('writer_lock_lost');
        throw failure();
      }
      try { return await operation(); }
      finally {
        // Provisioning also mutates SQLite. Save even failed scans/requests,
        // and never acknowledge a successful write before PostgreSQL commits.
        try {
          await checkWorkingDisk(this.dbFile, this.capacityAlerts);
          await this.save();
          if (!this.ready) throw failure();
          this.alerts.ready();
        } catch {
          this.healthy = false;
          this.alerts.fail('backup_failed');
          throw failure();
        }
        await this.checkSnapshotCapacity();
        await checkWorkingDisk(this.dbFile, this.capacityAlerts);
      }
    });
    this.tail = run.catch(() => {});
    return run;
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    this.healthy = false;
    await this.tail;
    await this.client.end().catch(() => {});
  }
}

let storage: FindingsStorage | undefined;
let localReady = false;
let capacityAlerts = new FindingsCapacityAlerts();
export const findingsReady = () => {
  if (storage && !storage.ready) findingsAlerts.remind();
  return storage ? storage.ready : localReady;
};
export async function withFindingsStorage<T>(operation: () => Promise<T>) {
  if (storage) return storage.run(operation);
  // An unopened coordinator is not permission to fall back to local SQLite.
  if (!localReady) throw failure();
  const dbFile = process.env.DB_FILE || '/tmp/vata.db';
  await checkWorkingDisk(dbFile, capacityAlerts);
  try { return await operation(); }
  finally { await checkWorkingDisk(dbFile, capacityAlerts); }
}
export async function prepareFindingsStorage() {
  try {
    localReady = false;
    capacityAlerts = new FindingsCapacityAlerts(readFindingsCapacityThresholds());
    const mode = validateFindingsConfiguration();
    if (mode === 'local') {
      console.warn('Findings use LOCAL-ONLY SQLite: data will not survive a replacement deployment.');
      await checkWorkingDisk(process.env.DB_FILE || '/tmp/vata.db', capacityAlerts);
      localReady = true;
      return undefined;
    }
    storage = new FindingsStorage(process.env.DATABASE_URL!, process.env.VATA_FINDINGS_NAMESPACE!,
      process.env.DB_FILE!, findingsAlerts, capacityAlerts);
    await storage.open();
    return storage;
  } catch (error) {
    if (!(error instanceof FindingsWriterBusyError)) findingsAlerts.fail('startup_failed');
    throw error;
  }
}
