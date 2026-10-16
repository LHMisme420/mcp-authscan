import { test } from 'node:test';
import assert from 'node:assert/strict';
import { billingMode } from '../server/billingMode';
import { advancedBillingEnabled, billingStatus, requirePro } from '../server/billing';

test('stale test and live flags cannot reactivate payments', async () => {
  for (const nodeEnv of ['production', 'development']) {
    for (const mode of ['live', 'test', 'disabled']) {
      assert.equal(billingMode({ NODE_ENV: nodeEnv, VATA_BILLING_MODE: mode }), 'disabled');
    }
  }
  assert.equal(advancedBillingEnabled(), false);
});

test('account response preserves disabled billing contract without touching account data', async () => {
  const untouched = new Proxy({}, { get() { throw new Error('Account must not be read or modified'); } });
  assert.deepEqual(await billingStatus(untouched), {
    plan: 'free', status: 'disabled', available: false, mode: 'disabled',
    testMode: false, checkoutReady: false, price: null,
  });
  await requirePro(untouched);
});
