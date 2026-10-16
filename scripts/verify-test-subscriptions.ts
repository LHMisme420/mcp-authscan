import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import express from 'express';
import type Stripe from 'stripe';
import { pool } from '../server/db';
import { assertSandboxContext, getTestStripeClient, getTestStripeSync } from '../server/stripeSandbox';
import { testCatalogPrice, validTestPrice } from '../server/testCheckoutService';
import { createTestWebhookHandler } from '../server/testWebhook';
import { appOrigin } from '../server/appOrigin';

assertSandboxContext();
const stripe = await getTestStripeClient();
const price = await testCatalogPrice();
assert.ok(validTestPrice(price));
const run = randomUUID();
const metadata = { purpose: 'vata_test_checkout', vata_account_id: `rehearsal_${run}`, owner_user_id: `rehearsal_${run}` };
// In-memory signing fixture, not a real endpoint secret or a configured environment variable.
const secret = `whsec_${randomBytes(32).toString('hex')}`;
const replayOnly = process.argv.includes('--external-replay-only');
const external = process.argv.includes('--external') || replayOnly;
const externalUrl = `${appOrigin()}/api/test-checkout/webhook`;
let signingSecret = secret;
if (external) {
  assert.ok(new URL(externalUrl).hostname.endsWith('.replit.dev'), 'External rehearsal is restricted to Preview.');
  const account = await stripe.accounts.retrieve(null);
  const managed = await pool.query(
    'SELECT secret FROM stripe._managed_webhooks WHERE account_id=$1 AND url=$2 LIMIT 1',
    [account.id, externalUrl],
  );
  assert.ok(managed.rows[0]?.secret, 'Connect the test callback first.');
  signingSecret = managed.rows[0].secret;
}
const receiptIds: string[] = [];
let clockId: string | undefined;
const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const accountFingerprint = async () => (await pool.query(
  `SELECT md5(COALESCE(json_agg(x ORDER BY id)::text,'[]')) AS fingerprint
   FROM (SELECT id,clerk_user_id,subscription_tier FROM public.vata_accounts) x`,
)).rows[0].fingerprint;
const before = await accountFingerprint();

const app = express();
app.post('/notify', express.raw({ type: 'application/json' }), createTestWebhookHandler(async () => ({
  verify: (payload, signature) => stripe.webhooks.constructEventAsync(payload, signature, secret),
  subscriptionPurpose: async id => (await stripe.subscriptions.retrieve(id)).metadata.purpose,
  sync: await getTestStripeSync(secret),
})));
const server = app.listen(0, '127.0.0.1');
await new Promise<void>(resolve => server.once('listening', resolve));
const base = `http://127.0.0.1:${(server.address() as any).port}`;
async function send(event: Stripe.Event, badSignature = false) {
  const payload = JSON.stringify(event);
  const signature = stripe.webhooks.generateTestHeaderString({ payload, secret: badSignature ? 'invalid_fixture' : signingSecret });
  const response = await fetch(external ? externalUrl : `${base}/notify`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'stripe-signature': signature }, body: payload,
  });
  const body = await response.json() as any;
  assert.equal(response.status, badSignature ? 400 : 200, JSON.stringify(body));
  return body;
}
async function receive(event: Stripe.Event) {
  if (!external || replayOnly) return send(event);
  // Observe a real Stripe-origin delivery before making any manual replay.
  for (let attempt = 0; attempt < 60; attempt++) {
    const receipt = await pool.query('SELECT 1 FROM public.vata_test_webhook_receipts WHERE event_id=$1', [event.id]);
    if (receipt.rowCount) return;
    await pause(1000);
  }
  throw new Error(`A real Stripe ${event.type} callback did not arrive. External delivery is not verified.`);
}
async function eventFor(type: string, id: string) {
  for (let attempt = 0; attempt < 25; attempt++) {
    const events = await stripe.events.list({ type, limit: 100 });
    const event = events.data.find(e => (e.data.object as any).id === id && e.livemode === false);
    if (event) { receiptIds.push(event.id); return event; }
    await pause(1000);
  }
  throw new Error(`Stripe did not produce the expected ${type} event.`);
}
async function mirroredStatus(id: string) {
  return (await pool.query('SELECT status FROM stripe.subscriptions WHERE id=$1', [id])).rows[0]?.status;
}
async function customer(paymentMethod: string) {
  const customer = await stripe.customers.create({
    name: 'VATA synthetic subscription rehearsal', test_clock: clockId, metadata,
  });
  assert.equal(customer.livemode, false);
  const method = await stripe.paymentMethods.attach(paymentMethod, { customer: customer.id });
  await stripe.customers.update(customer.id, { invoice_settings: { default_payment_method: method.id } });
  return { customer, method };
}
try {
  const clock = await stripe.testHelpers.testClocks.create({
    frozen_time: Math.floor(Date.now() / 1000), name: `VATA sandbox rehearsal ${run}`,
  });
  assert.equal(clock.livemode, false);
  clockId = clock.id;
  const good = await customer('pm_card_visa');
  let subscription = await stripe.subscriptions.create({
    customer: good.customer.id, items: [{ price: price.id }], default_payment_method: good.method.id, metadata,
  }, { idempotencyKey: `vata-rehearsal:${run}:subscription` });
  assert.equal(subscription.livemode, false);
  assert.equal(subscription.status, 'active');
  const duplicateCreation = await stripe.subscriptions.create({
    customer: good.customer.id, items: [{ price: price.id }], default_payment_method: good.method.id, metadata,
  }, { idempotencyKey: `vata-rehearsal:${run}:subscription` });
  assert.equal(duplicateCreation.id, subscription.id, 'A retry created a duplicate subscription.');
  const initialInvoice = await stripe.invoices.retrieve(
    typeof subscription.latest_invoice === 'string' ? subscription.latest_invoice : subscription.latest_invoice!.id,
  );
  assert.equal(initialInvoice.status, 'paid');
  const created = await eventFor('customer.subscription.created', subscription.id);
  await send(created, true);
  await receive(created);
  const duplicates = await Promise.all([send(created), send(created)]);
  assert.ok(duplicates.every(body => body.duplicate === true));
  assert.equal(await mirroredStatus(subscription.id), 'active');
  console.log('PASS: real test payment, active subscription, signed event, duplicate checkout and concurrent notification retries.');

  const declined = await customer('pm_card_chargeCustomerFail');
  const incomplete = await stripe.subscriptions.create({
    customer: declined.customer.id, items: [{ price: price.id }], default_payment_method: declined.method.id, metadata,
  });
  assert.equal(incomplete.status, 'incomplete');
  await receive(await eventFor('customer.subscription.created', incomplete.id));
  assert.equal(await mirroredStatus(incomplete.id), 'incomplete');
  console.log('PASS: declined initial test payment remains incomplete, never active.');

  const bad = await stripe.paymentMethods.attach('pm_card_chargeCustomerFail', { customer: good.customer.id });
  await stripe.subscriptions.update(subscription.id, { default_payment_method: bad.id });
  const target = subscription.items.data[0].current_period_end + 7200;
  await stripe.testHelpers.testClocks.advance(clock.id, { frozen_time: target });
  let ready = false;
  for (let attempt = 0; attempt < 90; attempt++) {
    const state = await stripe.testHelpers.testClocks.retrieve(clock.id);
    if (state.status === 'ready') { ready = true; break; }
    if (state.status === 'internal_failure') throw new Error('Stripe test clock failed.');
    await pause(1000);
  }
  assert.ok(ready, 'Stripe test clock did not finish.');
  subscription = await stripe.subscriptions.retrieve(subscription.id);
  const renewalId = typeof subscription.latest_invoice === 'string' ? subscription.latest_invoice : subscription.latest_invoice!.id;
  assert.notEqual(renewalId, initialInvoice.id);
  let renewal = await stripe.invoices.retrieve(renewalId);
  if (renewal.status === 'draft') renewal = await stripe.invoices.finalizeInvoice(renewal.id);
  if (!renewal.attempted) {
    try { await stripe.invoices.pay(renewal.id); }
    catch (error: any) { if (error.type !== 'StripeCardError') throw error; }
  }
  subscription = await stripe.subscriptions.retrieve(subscription.id);
  assert.equal(subscription.status, 'past_due');
  await receive(await eventFor('invoice.payment_failed', renewal.id));
  // A subscription update is the authoritative subscription-status notification.
  const failedEvent = await eventFor('customer.subscription.updated', subscription.id);
  await receive(failedEvent);
  assert.equal(await mirroredStatus(subscription.id), 'past_due');
  console.log('PASS: a real test-clock renewal fails and synchronizes past_due status.');

  const canceled = await stripe.subscriptions.cancel(subscription.id);
  assert.equal(canceled.status, 'canceled');
  await receive(await eventFor('customer.subscription.deleted', subscription.id));
  assert.equal(await mirroredStatus(subscription.id), 'canceled');
  // Replaying old notifications must not restore a canceled subscription.
  const old = { ...created, id: `evt_rehearsal${randomUUID().replaceAll('-', '')}` };
  receiptIds.push(old.id);
  await send(old);
  assert.equal(await mirroredStatus(subscription.id), 'canceled');
  assert.equal(await accountFingerprint(), before, 'Workspace ownership or tier was changed.');
  console.log('PASS: cancellation, stale-event protection and unchanged account access.');
  console.log(external && !replayOnly
    ? 'PASS: actual Stripe-origin callbacks reached Preview; signed replay and account-isolation checks passed. Browser card entry was NOT tested.'
    : replayOnly
      ? 'PASS: signed HTTP replays reached Preview and updated its database correctly. Automatic Stripe-origin delivery and browser card entry remain UNVERIFIED.'
      : 'External webhook delivery and browser card entry were NOT tested. No endpoint or privacy settings were changed.');
} finally {
  try {
    if (clockId) {
      await stripe.testHelpers.testClocks.del(clockId);
      console.log('Synthetic test clock, customers and subscriptions removed from Stripe.');
    }
    if (receiptIds.length) await pool.query(
      'DELETE FROM public.vata_test_webhook_receipts WHERE event_id=ANY($1::text[])', [receiptIds],
    );
  } finally {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await pool.end();
  }
}
