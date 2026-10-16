import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { runMigrations } from 'stripe-replit-sync';
import { getStripeSync, getUncachableStripeClient } from '../server/stripeClient';
import { assertStripeMode, billingMode } from '../server/billingMode';
import { appOrigin } from '../server/appOrigin';
import { pool } from '../server/db';
import { PRO_LOOKUP_KEY, PRO_PRICE, validProPrice } from '../server/billingPolicy';

// Operator-only setup, never imported or run by server startup or Publish.
// Creates a catalog, portal and scoped callback, never a customer or charge.
let sync: Awaited<ReturnType<typeof getStripeSync>> | undefined;
let stage = 'approval';
try {
  assert.equal(billingMode(), 'live', 'Live setup requires an explicitly configured production environment.');
  assert.ok(process.argv.includes('--confirm-live-catalog'), 'Confirm live catalog setup explicitly.');
  const origin = new URL(appOrigin());
  assert.ok(origin.protocol === 'https:' && !origin.hostname.endsWith('.replit.dev') &&
    !['localhost', '127.0.0.1'].includes(origin.hostname), 'A public production origin is required.');
  const endpoint = `${origin.origin}/api/stripe/webhook`;
  stage = 'live_authorization';
  const stripe = await getUncachableStripeClient();
  assertStripeMode((await stripe.balance.retrieve()).livemode, 'live');
  const account = await stripe.accounts.retrieve(null);
  assert.ok(account.charges_enabled, 'Stripe account must be enabled for live charges.');
  stage = 'public_callback';
  const response = await fetch(endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    redirect: 'manual', signal: AbortSignal.timeout(15000),
  });
  assert.equal(response.status, 400, 'Publish the live-enabled callback before running setup.');
  assert.equal((await response.json() as any).error, 'Missing webhook signature.');
  stage = 'billing_schema';
  assert.ok(process.env.DATABASE_URL, 'Billing database is required.');
  await runMigrations({ databaseUrl: process.env.DATABASE_URL });
  await pool.query(await readFile(path.resolve('migrations/live-billing.sql'), 'utf8'));
  sync = await getStripeSync('', 'live');
  stage = 'scoped_webhook';
  const existing = await sync.getManagedWebhookByUrl(endpoint);
  if (existing) {
    const remote = await stripe.webhookEndpoints.retrieve(existing.id);
    assert.equal(remote.url, endpoint);
    assert.equal(remote.livemode, true);
    assert.equal(remote.metadata.purpose, 'vata_pro_billing');
    assert.equal(remote.status, 'enabled', 'An existing disabled callback must be reviewed, not silently enabled.');
    for (const type of ['product.updated', 'customer.subscription.updated', 'customer.subscription.deleted',
      'invoice.paid', 'invoice.payment_failed', 'checkout.session.completed']) {
      assert.ok(remote.enabled_events.includes(type) || remote.enabled_events.includes('*'), 'Required event is missing.');
    }
  } else {
    for await (const remote of stripe.webhookEndpoints.list({ limit: 100 })) {
      assert.notEqual(remote.url, endpoint, 'A callback exists without its managed secret; it was not replaced.');
    }
    const webhook = await stripe.webhookEndpoints.create({
      url: endpoint,
      enabled_events: [
        'checkout.session.completed', 'checkout.session.expired',
        'customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted',
        'invoice.paid', 'invoice.payment_failed',
        'product.created', 'product.updated', 'price.created', 'price.updated',
      ],
      metadata: { app: 'vata', purpose: 'vata_pro_billing' },
    });
    try { await sync.upsertManagedWebhooks([webhook], account.id); }
    catch (error) {
      // Roll back only the endpoint just created here. Never touch prior callbacks.
      await stripe.webhookEndpoints.del(webhook.id);
      throw error;
    }
  }
  const startedAt = new Date();
  stage = 'fixed_catalog';
  const prices = await stripe.prices.list({ lookup_keys: [PRO_LOOKUP_KEY], limit: 2, expand: ['data.product'] });
  assert.ok(prices.data.length <= 1 && !prices.has_more, 'Ambiguous catalog requires review.');
  let price = prices.data[0];
  if (!price) {
    const product = await stripe.products.create({
      name: 'VATA Pro',
      description: 'API access, automated MCP scans, and up to five workspace seats. Basic scans and full history remain free.',
      metadata: { vata_plan: 'pro' },
    }, { idempotencyKey: 'vata-live-pro-product-v1' });
    price = await stripe.prices.create({
      product: product.id, unit_amount: PRO_PRICE.amount, currency: PRO_PRICE.currency,
      recurring: { interval: PRO_PRICE.interval }, lookup_key: PRO_LOOKUP_KEY, expand: ['product'],
    }, { idempotencyKey: 'vata-live-pro-usd-monthly-v1' });
  }
  assert.ok(validProPrice(price, true), 'The live catalog must be exactly $99 USD/month.');
  const productId = typeof price.product === 'string' ? price.product : price.product.id;
  await sync.syncSingleEntity(productId);
  await sync.syncSingleEntity(price.id);
  stage = 'billing_portal';
  let portalExists = false;
  for await (const configuration of stripe.billingPortal.configurations.list({ active: true, limit: 100 })) {
    if (configuration.metadata?.vata_portal === 'live_v1') portalExists = true;
  }
  if (!portalExists) await stripe.billingPortal.configurations.create({
    business_profile: { headline: 'Manage your VATA Pro subscription' },
    metadata: { vata_portal: 'live_v1' },
    features: {
      customer_update: { enabled: false }, invoice_history: { enabled: true },
      payment_method_update: { enabled: true },
      subscription_cancel: { enabled: true, mode: 'at_period_end' },
      subscription_update: { enabled: false },
    },
  }, { idempotencyKey: 'vata-live-portal-v1' });
  stage = 'actual_webhook_delivery';
  // A harmless catalog update triggers a real signed LIVE event, not a forged
  // local replay and not a test checkout. No customer or subscription is created.
  await stripe.products.update(productId, { metadata: { vata_delivery_check: new Date().toISOString() } });
  const deadline = Date.now() + 90000;
  let delivered = false;
  while (Date.now() < deadline) {
    const result = await pool.query(
      `SELECT 1 FROM public.vata_billing_webhook_receipts
       WHERE stripe_account_id=$1 AND livemode=true AND endpoint_url=$2
       AND event_type IN ('product.created','product.updated','price.created','price.updated')
       AND processed_at >= $3 LIMIT 1`, [account.id, endpoint, startedAt],
    );
    if (result.rowCount) { delivered = true; break; }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  assert.ok(delivered, 'No signed catalog delivery arrived. Checkout stays closed until Stripe delivery succeeds.');
  console.info('Live catalog, portal and signed webhook delivery verified. No customers, subscriptions or charges were created.');
} catch {
  // Stripe errors can include private request details, never print raw errors.
  console.error(`Live billing preparation did not complete (${stage}). Review authorization, published settings and Stripe delivery history. No charges were created by this script.`);
  process.exitCode = 1;
} finally {
  if (sync) await sync.postgresClient.pool.end();
  await pool.end();
}
