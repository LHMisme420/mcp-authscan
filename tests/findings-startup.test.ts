import test from 'node:test';
import assert from 'node:assert/strict';
import { acquireFindingsWriter, writerStartupPolicy } from '../server/findingsStartup';
import { findingsReady, withFindingsStorage } from '../server/findingsStorage';

test('writer startup waits are bounded and settings reject invalid values without echoing input', () => {
  assert.deepEqual(writerStartupPolicy({}), { timeoutMs: 120000, retryMs: 1000 });
  assert.deepEqual(writerStartupPolicy({
    VATA_FINDINGS_LOCK_TIMEOUT_MS: '2500', VATA_FINDINGS_LOCK_RETRY_MS: '100',
  }), { timeoutMs: 2500, retryMs: 100 });
  for (const name of ['VATA_FINDINGS_LOCK_TIMEOUT_MS', 'VATA_FINDINGS_LOCK_RETRY_MS']) {
    for (const value of ['', '0', '-1', '1.5', 'Infinity', '300001', 'fixture-private-value']) {
      assert.throws(() => writerStartupPolicy({ [name]: value }), error => {
        assert.ok(error instanceof Error);
        assert.match(error.message, new RegExp(name));
        assert.doesNotMatch(error.message, /fixture-private-value/);
        return true;
      });
    }
  }
});

test('uninitialized storage cannot silently become a local writer', async () => {
  assert.equal(findingsReady(), false);
  let ran = false;
  await assert.rejects(withFindingsStorage(async () => { ran = true; }), /Findings backup unavailable/);
  assert.equal(ran, false);
});

test('shutdown before acquisition never opens a database connection', async () => {
  const shutdown = new AbortController();
  shutdown.abort();
  await assert.rejects(acquireFindingsWriter(shutdown.signal), { name: 'AbortError' });
});
