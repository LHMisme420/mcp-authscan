import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { FindingsConnectionError, FindingsWriterBusyError, prepareFindingsStorage, type FindingsStorage } from './findingsStorage';

function setting(env: NodeJS.ProcessEnv, name: string, fallback: number, maximum: number) {
  const raw = env[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${name} must be an integer from 1 to ${maximum}.`);
  }
  return value;
}

export function scannerStartupTimeout(env: NodeJS.ProcessEnv = process.env) {
  return setting(env, 'VATA_SCANNER_STARTUP_TIMEOUT_MS', 120000, 300000);
}

export function writerStartupPolicy(env: NodeJS.ProcessEnv = process.env) {
  return {
    timeoutMs: setting(env, 'VATA_FINDINGS_LOCK_TIMEOUT_MS', 120000, 300000),
    retryMs: setting(env, 'VATA_FINDINGS_LOCK_RETRY_MS', 1000, 5000),
  };
}

/** Recovery retries connection loss too, but never retries integrity failures. */
export async function acquireFindingsWriter(
  signal: AbortSignal,
  policy = writerStartupPolicy(),
  recovering = false,
) {
  const deadline = performance.now() + policy.timeoutMs;
  let waiting = false;
  let attempt = 0;
  const timedOut = () => new Error(`Findings writer lock acquisition timed out after ${policy.timeoutMs}ms. Another findings writer is active; writes remained blocked.`);
  while (true) {
    signal.throwIfAborted();
    if (waiting && performance.now() >= deadline) throw timedOut();
    try {
      const storage = await prepareFindingsStorage();
      if (signal.aborted) {
        await storage?.close();
        signal.throwIfAborted();
      }
      return storage;
    } catch (error) {
      if (!(error instanceof FindingsWriterBusyError) &&
          !(recovering && error instanceof FindingsConnectionError)) throw error;
      signal.throwIfAborted();
      const remaining = deadline - performance.now();
      if (remaining <= 0) throw timedOut();
      if (!waiting) {
        waiting = true;
        console.info(JSON.stringify({
          event: 'findings_writer_waiting', severity: 'info',
          message: recovering
            ? 'Frontend is live; scanner APIs remain unavailable while writer ownership and connectivity recover.'
            : 'Frontend is live; scanner APIs remain unavailable while the previous findings writer drains.',
          timeoutMs: policy.timeoutMs,
        }));
      }
      const backoff = recovering ? Math.min(5000, policy.retryMs * 2 ** Math.min(attempt++, 4)) : policy.retryMs;
      await delay(Math.min(backoff, remaining), undefined, { signal });
    }
  }
}

/** Drain old work before a fresh session verifies exclusive ownership AND data.
 * open() refuses divergent local/durable files; recovery never overwrites either.
 */
export async function recoverFindingsWriter(
  previous: FindingsStorage,
  signal: AbortSignal,
  policy = writerStartupPolicy(),
) {
  await previous.close();
  signal.throwIfAborted();
  return acquireFindingsWriter(signal, policy, true);
}
