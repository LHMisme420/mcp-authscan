/**
 * Operator-run Google Cloud Storage delivery for encrypted recovery archives.
 * Intended for a private Cloud Run Job using its service account credentials.
 */
import { Storage } from '@google-cloud/storage';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { exportArchive } from './recovery-archive';

type RecoveryFile = {
  name: string;
  getMetadata(): Promise<[Record<string, any>]>;
  setMetadata(metadata: Record<string, unknown>): Promise<unknown>;
  download(options: { destination: string }): Promise<unknown>;
  delete(options?: Record<string, unknown>): Promise<unknown>;
  copy(destination: RecoveryFile, options?: Record<string, unknown>): Promise<unknown>;
};

type RecoveryBucket = {
  getMetadata(): Promise<[Record<string, any>]>;
  file(name: string): RecoveryFile;
  getFiles(options: { prefix: string }): Promise<[RecoveryFile[]]>;
  upload(localPath: string, options: Record<string, unknown>): Promise<unknown>;
};

type RecoveryStorage = {
  bucket(name: string): RecoveryBucket;
};

type Exporter = (sourceUrl: string, keyFile: string, destination: string) => Promise<void>;

const DAY_MS = 24 * 60 * 60 * 1000;
const VERIFIED_FIELD = 'backupState';
const VERIFIED_VALUE = 'verified';

function utcStamp(date: Date) {
  if (!Number.isFinite(date.getTime())) throw new Error('Invalid recovery schedule time.');
  return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

export function dailyObjectName(date: Date) {
  return `daily/${utcStamp(date)}.vata-dr`;
}

export function monthlyObjectName(date: Date) {
  if (!Number.isFinite(date.getTime())) throw new Error('Invalid recovery schedule time.');
  return `monthly/${date.toISOString().slice(0, 7)}.vata-dr`;
}

function dailyDate(name: string): string | undefined {
  const match = /^daily\/(\d{4})(\d{2})(\d{2})T\d{6}Z\.vata-dr$/.exec(name);
  return match ? `${match[1]}-${match[2]}-${match[3]}` : undefined;
}

function monthlyLabel(name: string): string | undefined {
  const match = /^monthly\/(\d{4})-(\d{2})\.vata-dr$/.exec(name);
  return match ? `${match[1]}-${match[2]}` : undefined;
}

function cutoffDay(date: Date, keepDays: number) {
  const cutoff = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  cutoff.setUTCDate(cutoff.getUTCDate() - keepDays + 1);
  return cutoff.toISOString().slice(0, 10);
}

function cutoffMonth(date: Date, keepMonths: number) {
  const month = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1));
  month.setUTCMonth(month.getUTCMonth() - keepMonths + 1);
  return month.toISOString().slice(0, 7);
}

export function expiredDailyNames(names: string[], now: Date, keepDays = 30) {
  const cutoff = cutoffDay(now, keepDays);
  return names.filter(name => {
    const date = dailyDate(name);
    return date !== undefined && date < cutoff;
  });
}

export function expiredMonthlyNames(names: string[], now: Date, keepMonths = 12) {
  const cutoff = cutoffMonth(now, keepMonths);
  return names.filter(name => {
    const month = monthlyLabel(name);
    return month !== undefined && month < cutoff;
  });
}

export function decodeRecoveryKey(encoded: string) {
  const normalized = encoded.trim();
  const key = Buffer.from(normalized, 'base64');
  if (key.length !== 32 || key.toString('base64') !== normalized) {
    key.fill(0);
    throw new Error('The Secret Manager recovery key must be canonical base64 for exactly 32 random bytes.');
  }
  return key;
}

async function sha256File(filePath: string) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

function customMetadata(metadata: Record<string, any>) {
  return (metadata.metadata && typeof metadata.metadata === 'object')
    ? metadata.metadata as Record<string, string>
    : {};
}

async function listVerified(bucket: RecoveryBucket, prefix: string) {
  const [files] = await bucket.getFiles({ prefix });
  const verified: Array<{ file: RecoveryFile; metadata: Record<string, any> }> = [];
  for (const file of files) {
    const [metadata] = await file.getMetadata();
    if (customMetadata(metadata)[VERIFIED_FIELD] === VERIFIED_VALUE) {
      verified.push({ file, metadata });
    }
  }
  return verified;
}

function ageHours(files: Array<{ file: RecoveryFile; metadata: Record<string, any> }>, now: Date) {
  const times = files.map(item => {
    const custom = customMetadata(item.metadata);
    const verifiedAt = Date.parse(custom.verifiedAt ?? '');
    if (Number.isFinite(verifiedAt)) return verifiedAt;
    const date = dailyDate(item.file.name);
    return date ? Date.parse(`${date}T00:00:00Z`) : Number.NaN;
  }).filter(Number.isFinite);
  if (!times.length) return null;
  return Math.max(0, Math.floor((now.getTime() - Math.max(...times)) / (60 * 60 * 1000)));
}

async function ensurePrivateBucket(bucket: RecoveryBucket) {
  const [metadata] = await bucket.getMetadata();
  const hasAutomaticDelete = Array.isArray(metadata.lifecycle?.rule)
    && metadata.lifecycle.rule.some((rule: Record<string, any>) => rule.action?.type === 'Delete');
  if (metadata.iamConfiguration?.uniformBucketLevelAccess?.enabled !== true
      || metadata.iamConfiguration?.publicAccessPrevention !== 'enforced'
      || metadata.location !== 'US'
      || metadata.locationType !== 'multi-region'
      || String(metadata.storageClass).toUpperCase() !== 'STANDARD'
      || hasAutomaticDelete
      || metadata.retentionPolicy?.isLocked === true) {
    throw new Error('Recovery bucket settings do not match the approved private US multi-region Standard configuration.');
  }
}

async function deleteOldVerified(
  bucket: RecoveryBucket,
  prefix: string,
  expired: (names: string[]) => string[],
  keepAtLeast: number,
) {
  const verified = await listVerified(bucket, prefix);
  if (verified.length <= keepAtLeast) return 0;
  const old = new Set(expired(verified.map(item => item.file.name)));
  let deleted = 0;
  for (const item of verified) {
    if (!old.has(item.file.name) || verified.length - deleted <= keepAtLeast) continue;
    const generation = item.metadata.generation;
    await item.file.delete(generation ? { ifGenerationMatch: generation } : undefined);
    deleted++;
  }
  return deleted;
}

/**
 * Creates one encrypted daily archive, uploads it without overwriting, downloads
 * it again for SHA-256 verification, retains a monthly verified copy, then
 * prunes only expired verified objects after the new recovery point is proven.
 */
export async function runDailyRecovery(options: {
  storage: RecoveryStorage;
  bucketName: string;
  sourceUrl: string;
  keyFile: string;
  now?: Date;
  exporter?: Exporter;
  tempRoot?: string;
}) {
  const now = options.now ?? new Date();
  const exporter = options.exporter ?? exportArchive;
  const bucket = options.storage.bucket(options.bucketName);
  let lastVerifiedAgeHours: number | null = null;
  let tempDirectory: string | undefined;

  try {
    await ensurePrivateBucket(bucket);
    const beforeDaily = await listVerified(bucket, 'daily/');
    lastVerifiedAgeHours = ageHours(beforeDaily, now);
    tempDirectory = await mkdtemp(path.join(options.tempRoot ?? tmpdir(), 'vata-gcs-recovery-'));
    await chmod(tempDirectory, 0o700);
    const localArchive = path.join(tempDirectory, 'daily.vata-dr');
    const downloadedArchive = path.join(tempDirectory, 'downloaded.vata-dr');
    const objectName = dailyObjectName(now);

    await exporter(options.sourceUrl, options.keyFile, localArchive);
    const checksum = await sha256File(localArchive);
    const dailyFile = bucket.file(objectName);
    await bucket.upload(localArchive, {
      destination: objectName,
      resumable: true,
      preconditionOpts: { ifGenerationMatch: 0 },
      metadata: {
        contentType: 'application/octet-stream',
        metadata: { sha256: checksum, backupState: 'pending' },
      },
    });
    await dailyFile.download({ destination: downloadedArchive });
    if (await sha256File(downloadedArchive) !== checksum) {
      throw new Error('Downloaded daily archive checksum did not match.');
    }
    await dailyFile.setMetadata({
      metadata: { sha256: checksum, backupState: VERIFIED_VALUE, verifiedAt: now.toISOString() },
    });

    const monthName = monthlyObjectName(now);
    const monthFile = bucket.file(monthName);
    const [monthFiles] = await bucket.getFiles({ prefix: monthName });
    const existingMonth = monthFiles.find(file => file.name === monthName);
    if (existingMonth) {
      const [metadata] = await existingMonth.getMetadata();
      if (customMetadata(metadata)[VERIFIED_FIELD] !== VERIFIED_VALUE) {
        // The current daily object is already independently verified. It is now
        // safe to replace an interrupted, unverified monthly attempt.
        await existingMonth.delete(metadata.generation ? { ifGenerationMatch: metadata.generation } : undefined);
      }
    }
    const [refreshedMonthFiles] = await bucket.getFiles({ prefix: monthName });
    const verifiedMonthExists = await Promise.all(refreshedMonthFiles
      .filter(file => file.name === monthName)
      .map(async file => {
        const [metadata] = await file.getMetadata();
        return customMetadata(metadata)[VERIFIED_FIELD] === VERIFIED_VALUE;
      }));
    if (!verifiedMonthExists.some(Boolean)) {
      await dailyFile.copy(monthFile, {
        preconditionOpts: { ifGenerationMatch: 0 },
        metadata: { sha256: checksum, backupState: 'pending' },
      });
      await monthFile.download({ destination: downloadedArchive });
      if (await sha256File(downloadedArchive) !== checksum) {
        throw new Error('Downloaded monthly archive checksum did not match.');
      }
      await monthFile.setMetadata({
        metadata: { sha256: checksum, backupState: VERIFIED_VALUE, verifiedAt: now.toISOString() },
      });
    }

    let expiredDaily = 0;
    let expiredMonthly = 0;
    try {
      expiredDaily = await deleteOldVerified(
        bucket, 'daily/', names => expiredDailyNames(names, now), 1,
      );
      expiredMonthly = await deleteOldVerified(
        bucket, 'monthly/', names => expiredMonthlyNames(names, now), 1,
      );
    } catch {
      console.error(JSON.stringify({
        event: 'recovery_retention_cleanup_failed',
        at: now.toISOString(),
        lastVerifiedAgeHours: 0,
      }));
    }

    console.log(JSON.stringify({
      event: 'independent_recovery_backup_verified',
      at: now.toISOString(),
      lastVerifiedAgeHours: 0,
      dailyObject: objectName,
      monthlyObject: monthName,
      checksum,
      dailyRetentionDeleted: expiredDaily,
      monthlyRetentionDeleted: expiredMonthly,
    }));
    return { objectName, monthName, checksum, expiredDaily, expiredMonthly };
  } catch {
    console.error(JSON.stringify({
      event: 'independent_recovery_backup_failed',
      at: now.toISOString(),
      lastVerifiedAgeHours,
      reason: 'operator_check_required',
    }));
    throw new Error('Independent recovery backup failed; inspect private operator logs and verify the last recovery point.');
  } finally {
    if (tempDirectory) await rm(tempDirectory, { recursive: true, force: true });
  }
}

async function main() {
  const [operation, approval, ...extra] = process.argv.slice(2);
  const sourceUrl = process.env.VATA_RECOVERY_SOURCE_URL;
  const encodedKey = process.env.VATA_RECOVERY_KEY_B64;
  const bucketName = process.env.VATA_RECOVERY_GCS_BUCKET;
  if (operation !== 'daily' || approval !== '--approve-sensitive-export' || extra.length
      || !sourceUrl || !encodedKey || !bucketName) {
    throw new Error('Explicit operator configuration and export approval are required.');
  }
  const key = decodeRecoveryKey(encodedKey);
  const keyDirectory = await mkdtemp(path.join(tmpdir(), 'vata-recovery-key-'));
  const keyFile = path.join(keyDirectory, 'recovery.key');
  try {
    await chmod(keyDirectory, 0o700);
    await writeFile(keyFile, key, { mode: 0o600, flag: 'wx' });
    await runDailyRecovery({
      storage: new Storage() as unknown as RecoveryStorage,
      bucketName,
      sourceUrl,
      keyFile,
    });
  } finally {
    key.fill(0);
    await rm(keyDirectory, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(() => {
    // Never print connection strings, key material, cloud tokens, or raw SDK errors.
    console.error(JSON.stringify({
      event: 'independent_recovery_configuration_failed',
      at: new Date().toISOString(),
      reason: 'operator_check_required',
    }));
    process.exitCode = 1;
  });
}
