import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FindingsAlerts, FindingsCapacityAlerts, FINDINGS_ALERT_INTERVAL_MS, FINDINGS_RECOVERY_LINK,
  readFindingsCapacityThresholds,
} from '../server/findingsAlerts';

test('operational alerts limit all failure types together and include only safe metadata', () => {
  let now = 0;
  const lines: string[] = [];
  const alerts = new FindingsAlerts(line => lines.push(line), () => now);
  alerts.fail('backup_failed');
  for (let i = 0; i < 100; i++) alerts.fail('writer_lock_lost');
  assert.equal(lines.length, 1);
  now = FINDINGS_ALERT_INTERVAL_MS - 1;
  alerts.remind();
  assert.equal(lines.length, 1);
  now++;
  alerts.remind();
  assert.deepEqual(JSON.parse(lines[1]), {
    event: 'findings_storage_unavailable', severity: 'critical', reason: 'backup_failed',
    message: 'Findings backup failed. Writes are paused; preserve the local database.',
    suppressed: 101, recovery: FINDINGS_RECOVERY_LINK,
  });
  assert.deepEqual(Object.keys(JSON.parse(lines[0])).sort(),
    ['event', 'message', 'reason', 'recovery', 'severity', 'suppressed']);
});

test('verification logs readiness once; recovery is immediate without resetting the failure limiter', () => {
  let now = 0;
  const events: any[] = [];
  const alerts = new FindingsAlerts(line => events.push(JSON.parse(line)), () => now);
  alerts.ready();
  alerts.ready();
  assert.deepEqual(events.map(e => e.event), ['findings_storage_ready']);
  alerts.fail('startup_failed');
  alerts.ready();
  alerts.ready();
  alerts.fail('backup_failed');
  assert.deepEqual(events.map(e => e.event),
    ['findings_storage_ready', 'findings_storage_unavailable', 'findings_storage_recovered']);
  now = FINDINGS_ALERT_INTERVAL_MS;
  alerts.remind();
  assert.equal(events.at(-1).reason, 'backup_failed');
  alerts.ready();
  assert.equal(events.at(-1).event, 'findings_storage_recovered');
});

test('capacity warnings trigger at configured limits, suppress repeats, and report recovery', () => {
  let now = 0;
  const events: any[] = [];
  const alerts = new FindingsCapacityAlerts(
    { snapshotBytes: 100, diskFreePercent: 20 },
    line => events.push(JSON.parse(line)),
    () => now,
    1000,
  );

  alerts.snapshotUsage(99);
  alerts.snapshotUsage(100);
  alerts.snapshotUsage(120);
  assert.equal(events.length, 1);
  assert.deepEqual(events[0], {
    event: 'findings_capacity_warning', severity: 'warning', metric: 'snapshot_bytes',
    observedBytes: 100, thresholdBytes: 100,
    message: 'Findings snapshots have reached the configured storage budget.',
    suppressed: 0, recovery: FINDINGS_RECOVERY_LINK,
  });

  alerts.snapshotUsage(99);
  assert.equal(events[1].event, 'findings_capacity_recovered');
  assert.equal(events[1].metric, 'snapshot_bytes');
  alerts.snapshotUsage(100);
  assert.equal(events.length, 2, 're-entry inside the interval remains rate limited');

  now = 1000;
  alerts.snapshotUsage(110);
  assert.equal(events[2].event, 'findings_capacity_warning');
  assert.equal(events[2].suppressed, 1);

  alerts.diskSpace(20, 100);
  assert.equal(events[3].metric, 'disk_free_percent');
  assert.equal(events[3].freePercent, 20);
  alerts.diskSpace(21, 100);
  assert.equal(events[4].event, 'findings_capacity_recovered');
  assert.equal(events[4].metric, 'disk_free_percent');

  for (const event of events) {
    assert.equal(JSON.stringify(event).includes('namespace'), false);
    assert.equal(JSON.stringify(event).includes('payload'), false);
  }
});

test('capacity probe failures are rate limited, recover, and expose only safe metadata', () => {
  let now = 0;
  const events: any[] = [];
  const alerts = new FindingsCapacityAlerts(
    { snapshotBytes: 100, diskFreePercent: 20 },
    line => events.push(JSON.parse(line)),
    () => now,
    1000,
  );

  alerts.probeFailed('postgresql');
  alerts.probeFailed('postgresql');
  assert.equal(events.length, 1);
  assert.deepEqual(events[0], {
    event: 'findings_capacity_probe_failed',
    severity: 'warning',
    probe: 'postgresql',
    message: 'Findings PostgreSQL capacity could not be measured.',
    suppressed: 0,
  });

  alerts.probeRecovered('postgresql');
  assert.deepEqual(events[1], {
    event: 'findings_capacity_probe_recovered',
    severity: 'info',
    probe: 'postgresql',
    message: 'Findings storage capacity measurement has recovered.',
    suppressed: 1,
  });
  assert.doesNotMatch(JSON.stringify(events), /path|namespace|credential|payload|private/i);

  now = 1000;
  alerts.probeFailed('postgresql');
  assert.equal(events[2].event, 'findings_capacity_probe_failed');
  assert.equal(events[2].suppressed, 0);
});

test('capacity logger failures do not escape telemetry reporting', () => {
  const alerts = new FindingsCapacityAlerts(
    { snapshotBytes: 100, diskFreePercent: 20 },
    () => { throw new Error('logger unavailable'); },
  );
  assert.doesNotThrow(() => alerts.probeFailed('filesystem'));
  assert.doesNotThrow(() => alerts.probeRecovered('filesystem'));
  assert.doesNotThrow(() => alerts.snapshotUsage(100));
  assert.doesNotThrow(() => alerts.diskSpace(10, 100));
});

test('capacity thresholds have operator-configurable defaults and reject invalid values', () => {
  assert.deepEqual(readFindingsCapacityThresholds({} as NodeJS.ProcessEnv), {
    snapshotBytes: 1024 ** 3, diskFreePercent: 15,
  });
  assert.deepEqual(readFindingsCapacityThresholds({
    VATA_FINDINGS_SNAPSHOT_WARN_BYTES: '2048',
    VATA_FINDINGS_DISK_WARN_FREE_PERCENT: '25',
  } as NodeJS.ProcessEnv), { snapshotBytes: 2048, diskFreePercent: 25 });
  assert.throws(() => readFindingsCapacityThresholds({
    VATA_FINDINGS_DISK_WARN_FREE_PERCENT: '100',
  } as NodeJS.ProcessEnv), /between 1 and 99/);
});
