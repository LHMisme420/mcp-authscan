import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  decodeRecoveryKey,
  dailyObjectName,
  expiredDailyNames,
  expiredMonthlyNames,
  monthlyObjectName,
  runDailyRecovery,
} from '../scripts/recovery-gcs';
import { randomBytes } from 'node:crypto';

type StoredObject = {
  data: Buffer;
  metadata: Record<string, string>;
  generation: string;
};

class FakeFile {
  constructor(private bucket: FakeBucket, public name: string) {}

  private get object() {
    const value = this.bucket.objects.get(this.name);
    if (!value) throw new Error('Object not found.');
    return value;
  }

  async getMetadata() {
    return [{
      generation: this.object.generation,
      metadata: { ...this.object.metadata },
      size: String(this.object.data.length),
    }];
  }

  async setMetadata(value: { metadata?: Record<string, string> }) {
    this.object.metadata = { ...this.object.metadata, ...(value.metadata ?? {}) };
  }

  async download(options: { destination: string }) {
    const data = Buffer.from(this.object.data);
    if (this.bucket.corruptDownloads && data.length) data[0] ^= 1;
    await writeFile(options.destination, data, { mode: 0o600 });
  }

  async delete(options?: { ifGenerationMatch?: string }) {
    if (options?.ifGenerationMatch
        && options.ifGenerationMatch !== this.object.generation) {
      throw new Error('Generation changed.');
    }
    this.bucket.objects.delete(this.name);
  }

  async copy(destination: FakeFile, options?: { metadata?: Record<string, string> }) {
    if (this.bucket.objects.has(destination.name)) throw new Error('Object already exists.');
    this.bucket.put(destination.name, this.object.data, options?.metadata ?? {});
  }
}

class FakeBucket {
  objects = new Map<string, StoredObject>();
  corruptDownloads = false;
  settings = {
    location: 'US',
    locationType: 'multi-region',
    storageClass: 'STANDARD',
    lifecycle: { rule: [] },
    retentionPolicy: { isLocked: false },
    iamConfiguration: {
      uniformBucketLevelAccess: { enabled: true },
      publicAccessPrevention: 'enforced',
    },
  };
  private generation = 0;

  getMetadata = async () => [this.settings];
  file(name: string) { return new FakeFile(this, name); }

  async getFiles(options: { prefix: string }) {
    return [[...this.objects.keys()]
      .filter(name => name.startsWith(options.prefix))
      .map(name => this.file(name))];
  }

  async upload(localPath: string, options: {
    destination: string;
    metadata?: { metadata?: Record<string, string> };
  }) {
    if (this.objects.has(options.destination)) throw new Error('Object already exists.');
    this.put(options.destination, await readFile(localPath), options.metadata?.metadata ?? {});
  }

  put(name: string, data: Buffer, metadata: Record<string, string>) {
    this.objects.set(name, {
      data: Buffer.from(data),
      metadata: { ...metadata },
      generation: String(++this.generation),
    });
  }
}

class FakeStorage {
  readonly bucketInstance = new FakeBucket();
  bucket() { return this.bucketInstance; }
}

test('recovery object names and UTC retention boundaries are stable', () => {
  const now = new Date('2026-10-15T04:05:06.000Z');
  assert.equal(dailyObjectName(now), 'daily/20261015T040506Z.vata-dr');
  assert.equal(monthlyObjectName(now), 'monthly/2026-10.vata-dr');
  assert.deepEqual(expiredDailyNames([
    'daily/20260915T235959Z.vata-dr',
    'daily/20260916T000000Z.vata-dr',
    'daily/not-an-archive',
  ], now), ['daily/20260915T235959Z.vata-dr']);
  assert.deepEqual(expiredMonthlyNames([
    'monthly/2025-10.vata-dr',
    'monthly/2025-11.vata-dr',
    'monthly/not-an-archive',
  ], now), ['monthly/2025-10.vata-dr']);
});

test('secret-manager key value decodes only to exactly 32 canonical bytes', () => {
  const key = randomBytes(32);
  assert.deepEqual(decodeRecoveryKey(`${key.toString('base64')}\n`), key);
  assert.throws(() => decodeRecoveryKey(Buffer.from('too short').toString('base64')), /exactly 32/);
});

test('daily upload is downloaded and checksummed before monthly retention is marked verified', async () => {
  const temp = await mkdtemp(path.join(tmpdir(), 'vata-gcs-test-'));
  try {
    const storage = new FakeStorage();
    const now = new Date('2026-10-15T04:05:06.000Z');
    const source = Buffer.from('synthetic encrypted archive bytes');
    const expectedChecksum = createHash('sha256').update(source).digest('hex');

    storage.bucketInstance.put('daily/20260901T000000Z.vata-dr', Buffer.from('old'), {
      backupState: 'verified',
    });
    storage.bucketInstance.put('monthly/2024-01.vata-dr', Buffer.from('old'), {
      backupState: 'verified',
    });

    const result = await runDailyRecovery({
      storage: storage as any,
      bucketName: 'synthetic-private-bucket',
      sourceUrl: 'synthetic-source',
      keyFile: 'synthetic-key',
      now,
      tempRoot: temp,
      exporter: async (_sourceUrl, _keyFile, destination) => {
        await writeFile(destination, source, { mode: 0o600 });
      },
    });

    const dailyName = 'daily/20261015T040506Z.vata-dr';
    const monthlyName = 'monthly/2026-10.vata-dr';
    assert.equal(result.objectName, dailyName);
    assert.equal(result.monthName, monthlyName);
    assert.equal(result.checksum, expectedChecksum);
    assert.equal(storage.bucketInstance.objects.get(dailyName)?.metadata.backupState, 'verified');
    assert.equal(storage.bucketInstance.objects.get(monthlyName)?.metadata.backupState, 'verified');
    assert.equal(storage.bucketInstance.objects.get(monthlyName)?.metadata.sha256, expectedChecksum);
    assert.equal(storage.bucketInstance.objects.has('daily/20260901T000000Z.vata-dr'), false);
    assert.equal(storage.bucketInstance.objects.has('monthly/2024-01.vata-dr'), false);
    assert.equal(storage.bucketInstance.objects.get(dailyName)?.data.equals(source), true);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('unsafe bucket settings fail before any archive is exported', async () => {
  const storage = new FakeStorage();
  storage.bucketInstance.settings.iamConfiguration.publicAccessPrevention = 'inherited';
  let exportAttempted = false;

  await assert.rejects(runDailyRecovery({
    storage: storage as any,
    bucketName: 'synthetic-public-bucket',
    sourceUrl: 'synthetic-source',
    keyFile: 'synthetic-key',
    now: new Date('2026-10-15T04:05:06.000Z'),
    exporter: async () => { exportAttempted = true; },
  }), /Independent recovery backup failed/);

  assert.equal(exportAttempted, false);
  assert.equal(storage.bucketInstance.objects.size, 0);
});

test('automatic bucket deletion rules are rejected before export', async () => {
  const storage = new FakeStorage();
  storage.bucketInstance.settings.lifecycle.rule = [{ action: { type: 'Delete' } }];
  let exportAttempted = false;

  await assert.rejects(runDailyRecovery({
    storage: storage as any,
    bucketName: 'synthetic-auto-delete-bucket',
    sourceUrl: 'synthetic-source',
    keyFile: 'synthetic-key',
    now: new Date('2026-10-15T04:05:06.000Z'),
    exporter: async () => { exportAttempted = true; },
  }), /Independent recovery backup failed/);

  assert.equal(exportAttempted, false);
});

test('a failed download checksum does not mark or prune recovery points', async () => {
  const temp = await mkdtemp(path.join(tmpdir(), 'vata-gcs-checksum-test-'));
  try {
    const storage = new FakeStorage();
    storage.bucketInstance.corruptDownloads = true;
    storage.bucketInstance.put('daily/20260901T000000Z.vata-dr', Buffer.from('verified old copy'), {
      backupState: 'verified',
      verifiedAt: '2026-09-01T00:00:00.000Z',
    });
    let now = new Date('2026-10-15T04:05:06.000Z');
    await assert.rejects(runDailyRecovery({
      storage: storage as any,
      bucketName: 'synthetic-private-bucket',
      sourceUrl: 'synthetic-source',
      keyFile: 'synthetic-key',
      now,
      tempRoot: temp,
      exporter: async (_sourceUrl, _keyFile, destination) => {
        await writeFile(destination, Buffer.from('new encrypted copy'), { mode: 0o600 });
      },
    }), /Independent recovery backup failed/);

    assert.equal(storage.bucketInstance.objects.get('daily/20260901T000000Z.vata-dr')?.metadata.backupState, 'verified');
    assert.equal(storage.bucketInstance.objects.get('daily/20261015T040506Z.vata-dr')?.metadata.backupState, 'pending');
    assert.equal(storage.bucketInstance.objects.has('monthly/2026-10.vata-dr'), false);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
