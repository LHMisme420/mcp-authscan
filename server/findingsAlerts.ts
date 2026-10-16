import { performance } from 'node:perf_hooks';

export const FINDINGS_ALERT_INTERVAL_MS = 15 * 60 * 1000;
export const FINDINGS_RECOVERY_LINK = 'docs/findings-storage.md#recovery-and-rollback';
export const DEFAULT_FINDINGS_SNAPSHOT_WARN_BYTES = 1024 ** 3;
export const DEFAULT_FINDINGS_DISK_WARN_FREE_PERCENT = 15;

export type FindingsCapacityThresholds = {
  snapshotBytes: number;
  diskFreePercent: number;
};

export const DEFAULT_FINDINGS_CAPACITY_THRESHOLDS: FindingsCapacityThresholds = {
  snapshotBytes: DEFAULT_FINDINGS_SNAPSHOT_WARN_BYTES,
  diskFreePercent: DEFAULT_FINDINGS_DISK_WARN_FREE_PERCENT,
};

function positiveIntegerSetting(env: NodeJS.ProcessEnv, name: string, fallback: number) {
  const raw = env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer.`);
  }
  return value;
}

export function readFindingsCapacityThresholds(env: NodeJS.ProcessEnv = process.env): FindingsCapacityThresholds {
  const snapshotBytes = positiveIntegerSetting(env, 'VATA_FINDINGS_SNAPSHOT_WARN_BYTES', DEFAULT_FINDINGS_SNAPSHOT_WARN_BYTES);
  const diskFreePercent = positiveIntegerSetting(env, 'VATA_FINDINGS_DISK_WARN_FREE_PERCENT', DEFAULT_FINDINGS_DISK_WARN_FREE_PERCENT);
  if (diskFreePercent > 99) throw new Error('VATA_FINDINGS_DISK_WARN_FREE_PERCENT must be between 1 and 99.');
  return { snapshotBytes, diskFreePercent };
}

const messages = {
  startup_failed: 'Findings backup could not be verified at startup. Service is unavailable.',
  backup_failed: 'Findings backup failed. Writes are paused; preserve the local database.',
  writer_lock_lost: 'Findings writer-lock session was lost. Writes are paused; preserve the local database.',
} as const;
export type FindingsFailure = keyof typeof messages;

/** Logs only allowlisted operational metadata, never errors or application data.
 * One limiter covers all failure types, so changing symptoms cannot flood logs.
 * State is process-local; a replacement emits its own verified-ready event.
 */
export class FindingsAlerts {
  private reason: FindingsFailure | undefined;
  private lastFailure = -Infinity;
  private suppressed = 0;
  private verified = false;

  constructor(
    private readonly emit: (line: string) => void = line => console.error(line),
    private readonly now: () => number = () => performance.now(),
  ) {}

  fail(reason: FindingsFailure) {
    this.reason ??= reason;
    this.remind();
  }

  remind() {
    if (!this.reason) return;
    const now = this.now();
    if (now - this.lastFailure < FINDINGS_ALERT_INTERVAL_MS) {
      this.suppressed++;
      return;
    }
    this.emit(JSON.stringify({
      event: 'findings_storage_unavailable', severity: 'critical',
      reason: this.reason, message: messages[this.reason],
      suppressed: this.suppressed, recovery: FINDINGS_RECOVERY_LINK,
    }));
    this.lastFailure = now;
    this.suppressed = 0;
  }

  /** Only after a successful writer probe AND snapshot/commit verification. */
  ready() {
    if (this.verified && !this.reason) return;
    this.emit(JSON.stringify({
      event: this.reason ? 'findings_storage_recovered' : 'findings_storage_ready',
      severity: 'info',
      message: 'Findings writer session and backup verified. Storage is ready.',
      recovery: FINDINGS_RECOVERY_LINK,
    }));
    this.verified = true;
    this.reason = undefined;
    this.suppressed = 0;
    // Do not reset lastFailure: repeated fail/recover flaps share the limiter.
  }
}

type CapacityMetric = 'snapshot_bytes' | 'disk_free_percent';
type CapacityState = { active: boolean; lastWarning: number; suppressed: number };
type CapacityProbe = 'filesystem' | 'postgresql';
type CapacityProbeState = { active: boolean; lastWarning: number; suppressed: number };

/** Capacity messages contain only aggregate sizes/percentages, never paths or database identifiers. */
export class FindingsCapacityAlerts {
  private readonly states: Record<CapacityMetric, CapacityState> = {
    snapshot_bytes: { active: false, lastWarning: -Infinity, suppressed: 0 },
    disk_free_percent: { active: false, lastWarning: -Infinity, suppressed: 0 },
  };
  private readonly probeStates: Record<CapacityProbe, CapacityProbeState> = {
    filesystem: { active: false, lastWarning: -Infinity, suppressed: 0 },
    postgresql: { active: false, lastWarning: -Infinity, suppressed: 0 },
  };

  constructor(
    readonly thresholds: FindingsCapacityThresholds = DEFAULT_FINDINGS_CAPACITY_THRESHOLDS,
    private readonly emit: (line: string) => void = line => console.warn(line),
    private readonly now: () => number = () => performance.now(),
    private readonly intervalMs = FINDINGS_ALERT_INTERVAL_MS,
  ) {}

  probeFailed(probe: CapacityProbe) {
    const state = this.probeStates[probe];
    state.active = true;
    const now = this.now();
    if (now - state.lastWarning < this.intervalMs) {
      state.suppressed++;
      return;
    }
    this.emitSafely(JSON.stringify({
      event: 'findings_capacity_probe_failed', severity: 'warning', probe,
      message: probe === 'filesystem'
        ? 'Findings filesystem capacity could not be measured.'
        : 'Findings PostgreSQL capacity could not be measured.',
      suppressed: state.suppressed,
    }));
    state.lastWarning = now;
    state.suppressed = 0;
  }

  probeRecovered(probe: CapacityProbe) {
    const state = this.probeStates[probe];
    if (!state.active) return;
    this.emitSafely(JSON.stringify({
      event: 'findings_capacity_probe_recovered', severity: 'info', probe,
      message: 'Findings storage capacity measurement has recovered.',
      suppressed: state.suppressed,
    }));
    state.active = false;
    state.suppressed = 0;
  }

  snapshotUsage(usedBytes: number) {
    this.report('snapshot_bytes', usedBytes >= this.thresholds.snapshotBytes, {
      observedBytes: usedBytes, thresholdBytes: this.thresholds.snapshotBytes,
    });
  }

  diskSpace(freeBytes: number, totalBytes: number) {
    const freePercent = totalBytes > 0 ? (freeBytes / totalBytes) * 100 : 100;
    this.report('disk_free_percent', freePercent <= this.thresholds.diskFreePercent, {
      freeBytes, totalBytes, freePercent: Math.round(freePercent * 10) / 10,
      thresholdPercent: this.thresholds.diskFreePercent,
    });
  }

  private report(metric: CapacityMetric, isHigh: boolean, values: Record<string, number>) {
    const state = this.states[metric];
    if (!isHigh) {
      if (!state.active) return;
      this.emitSafely(JSON.stringify({
        event: 'findings_capacity_recovered', severity: 'info', metric,
        message: 'Findings storage capacity is back within its configured threshold.',
        suppressed: state.suppressed, recovery: FINDINGS_RECOVERY_LINK,
      }));
      state.active = false;
      state.suppressed = 0;
      return;
    }

    state.active = true;
    const now = this.now();
    if (now - state.lastWarning < this.intervalMs) {
      state.suppressed++;
      return;
    }
    this.emitSafely(JSON.stringify({
      event: 'findings_capacity_warning', severity: 'warning', metric, ...values,
      message: metric === 'snapshot_bytes'
        ? 'Findings snapshots have reached the configured storage budget.'
        : 'The working filesystem has reached the configured low-free-space threshold.',
      suppressed: state.suppressed, recovery: FINDINGS_RECOVERY_LINK,
    }));
    state.lastWarning = now;
    state.suppressed = 0;
  }

  private emitSafely(line: string) {
    try { this.emit(line); }
    catch { /* Telemetry logging must never affect findings operations. */ }
  }
}

export const findingsAlerts = new FindingsAlerts();
