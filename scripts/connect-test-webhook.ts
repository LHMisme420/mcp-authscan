import assert from 'node:assert/strict';
import { pool } from '../server/db';
import { appOrigin } from '../server/appOrigin';
import { assertSandboxContext, getTestStripeClient, getTestStripeSync } from '../server/stripeSandbox';

assertSandboxContext();
const stripe = await getTestStripeClient(); // Reject live credentials before any external mutation.
const account = await stripe.accounts.retrieve(null);
const endpoint = `${appOrigin()}/api/test-checkout/webhook`;
const url = new URL(endpoint);
assert.ok(url.protocol === 'https:' && url.hostname.endsWith('.replit.dev'), 'Only this Preview callback may be registered.');
const readiness = await fetch(endpoint, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}', redirect: 'manual',
});
assert.equal(readiness.status, 400, 'Preview is not reachable at its signed notification handler.');
assert.equal((await readiness.json() as any).error, 'A raw, signed Stripe test notification is required.');
const sync = await getTestStripeSync();
const disable = process.argv.includes('--disable');
try {
  const existing = await sync.getManagedWebhookByUrl(endpoint);
  assert.ok(!disable || existing, 'There is no existing sandbox callback to disable.');
  const params = {
    url: endpoint,
    enabled_events: [
      'checkout.session.completed', 'checkout.session.expired',
      'customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted',
      'invoice.paid', 'invoice.payment_failed',
    ],
    metadata: { app: 'vata', purpose: 'vata_test_checkout', managed_by: 'vata-sandbox' },
  } as const;
  let webhook;
  if (existing) {
    webhook = await stripe.webhookEndpoints.retrieve(existing.id);
  } else {
    const remote = await stripe.webhookEndpoints.list({ limit: 100 });
    assert.ok(!remote.data.some(item => item.url === endpoint),
      'A callback already exists without its managed signing secret. It was not rotated or deleted.');
    webhook = await stripe.webhookEndpoints.create({ ...params, enabled_events: [...params.enabled_events] });
    try {
      // Add through the public SDK API. Its global find-or-create helper can
      // delete other managed URLs, which this sandbox setup must preserve.
      await sync.upsertManagedWebhooks([webhook], account.id);
    } catch (error) {
      await stripe.webhookEndpoints.del(webhook.id); // Roll back only the endpoint created by this invocation.
      throw error;
    }
  }
  assert.equal(webhook.livemode, false);
  assert.equal(webhook.url, endpoint);
  assert.equal(webhook.metadata.purpose, 'vata_test_checkout');
  if (disable || webhook.status === 'disabled') {
    webhook = await stripe.webhookEndpoints.update(webhook.id, { disabled: disable });
  }
  if (disable) {
    assert.equal(webhook.status, 'disabled');
    console.log('Only this sandbox callback was disabled. Existing callbacks and its managed signing secret were preserved.');
  } else {
  assert.equal(webhook.status, 'enabled');
  console.log('Stripe TEST callback connected to Preview. No production or privacy settings changed.');
  }
} finally {
  await sync.postgresClient.pool.end();
  await pool.end();
}
