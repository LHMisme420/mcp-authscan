import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import express from 'express';
import type { AddressInfo } from 'node:net';
import Stripe from 'stripe';
import { billingMode, assertStripeMode, stripeRedirect } from '../server/billingMode';
import { PRO_LOOKUP_KEY, PRO_PRICE, subscriptionGrantsAccess, validProPrice } from '../server/billingPolicy';
import { assertCustomerOwnership } from '../server/billing';
import { createBillingRoutes } from '../server/billingRoutes';
import { createBillingWebhookProcessor } from '../server/webhookHandlers';
import { oncePerBillingEvent } from '../server/billingWebhookReceipts';
import { requireOwner, TierError } from '../server/tiers';
import { pool } from '../server/db';

function liveEnvironment() {
  const previous = { NODE_ENV: process.env.NODE_ENV, VATA_BILLING_MODE: process.env.VATA_BILLING_MODE };
  process.env.NODE_ENV = 'production';
  process.env.VATA_BILLING_MODE = 'live';
  return () => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
}

const owner = { id: 42, clerk_user_id: 'synthetic-live-owner', stripe_customer_id: 'cus_legacy_test', role: 'owner' };
const metadata = { vata_account_id: '42', clerk_user_id: owner.clerk_user_id };
function price(livemode = true) {
  return {
    id: 'price_live_fixture', livemode, active: true, lookup_key: PRO_LOOKUP_KEY,
    currency: 'usd', unit_amount: 9900, recurring: { interval: 'month', interval_count: 1 },
    product: { id: 'prod_fixture', livemode, active: true, metadata: { vata_plan: 'pro' } },
  };
}

test('payments are disabled by default everywhere and live billing requires production opt-in', () => {
  assert.equal(billingMode({}), 'disabled');
  assert.equal(billingMode({ NODE_ENV: 'development' }), 'disabled');
  assert.equal(billingMode({ NODE_ENV: 'test' }), 'disabled');
  assert.equal(billingMode({ NODE_ENV: 'development', VATA_BILLING_MODE: 'test' }), 'test');
  assert.equal(billingMode({ NODE_ENV: 'production' }), 'disabled');
  assert.equal(billingMode({ NODE_ENV: 'production', VATA_BILLING_MODE: 'test' }), 'disabled');
  assert.equal(billingMode({ NODE_ENV: 'production', VATA_BILLING_MODE: 'live' }), 'live');
  for (const setting of ['live', 'disabled', 'typo']) {
    assert.equal(billingMode({ NODE_ENV: 'development', VATA_BILLING_MODE: setting }), 'disabled');
  }
  assert.doesNotThrow(() => assertStripeMode(true, 'live'));
  assert.doesNotThrow(() => assertStripeMode(false, 'test'));
  assert.throws(() => assertStripeMode(false, 'live'));
  assert.throws(() => assertStripeMode(true, 'test'));
  assert.throws(() => assertStripeMode(undefined, 'live'));
});

test('live catalog requires exactly $99 USD/month and cannot use a test price or inactive product', () => {
  assert.equal(validProPrice(price(), true), true);
  for (const candidate of [
    price(false), { ...price(), unit_amount: 990 }, { ...price(), currency: 'eur' },
    { ...price(), recurring: { interval: 'year', interval_count: 1 } },
    { ...price(), recurring: { interval: 'month', interval_count: 2 } },
    { ...price(), active: false }, { ...price(), lookup_key: 'other' },
    { ...price(), product: { ...price().product, active: false } },
    { ...price(), product: { ...price().product, metadata: {} } },
  ]) assert.equal(validProPrice(candidate, true), false);
});

test('test subscriptions never grant live Pro; cancellation and expiry remove live access', () => {
  const account = { ...owner, stripe_customer_id: 'cus_live_fixture' };
  const subscription = {
    livemode: true, customer: account.stripe_customer_id, metadata, status: 'active',
    items: { data: [{ price: { id: 'price_live_fixture' }, current_period_end: 2000000000 }] },
  };
  const now = 1800000000000;
  assert.equal(subscriptionGrantsAccess(subscription, 'price_live_fixture', account, now, true), true);
  assert.equal(subscriptionGrantsAccess({ ...subscription, livemode: false }, 'price_live_fixture', account, now, true), false);
  assert.equal(subscriptionGrantsAccess(subscription, 'price_live_fixture', owner, now, true), false);
  assert.equal(subscriptionGrantsAccess(subscription, 'price_live_fixture', account, 2000000000000, true), false);
  for (const status of ['incomplete', 'past_due', 'unpaid', 'canceled', 'paused']) {
    assert.equal(subscriptionGrantsAccess({ ...subscription, status }, 'price_live_fixture', account, now, true), false);
  }
  const restore = liveEnvironment();
  try {
    assert.doesNotThrow(() => assertCustomerOwnership({ livemode: true, metadata }, account));
    assert.throws(() => assertCustomerOwnership({ livemode: false, metadata }, account));
  } finally { restore(); }
});

test('billing redirects reject non-Stripe destinations and host lookalikes', () => {
  assert.equal(stripeRedirect('https://checkout.stripe.com/c/pay/fixture', 'checkout.stripe.com'),
    'https://checkout.stripe.com/c/pay/fixture');
  for (const url of ['https://evil.invalid', 'https://checkout.stripe.com.evil.invalid',
    'http://checkout.stripe.com', 'https://user:pass@checkout.stripe.com', 'javascript:alert(1)']) {
    assert.throws(() => stripeRedirect(url, 'checkout.stripe.com'));
  }
});

test('live owner checkout waits for delivery, isolates test customers, fixes price and supports the live portal', async t => {
  const restore = liveEnvironment();
  t.after(restore);
  let delivered = false, paid = false, priceMode = true, sessionMode = true;
  let liveCustomerId: string | null = null;
  let providerCalls = 0;
  let sessionUrl = 'https://checkout.stripe.com/c/pay/live_fixture';
  let created: any, portal: any, open: any[] = [], subscriptions: any[] = [];
  const synced: string[] = [];
  const customer = { id: 'cus_live_fixture', livemode: true, metadata };
  const client = {
    query: async (sql: string) => ({ rows: sql.startsWith('SELECT *') ? [{ ...owner }] : [] }),
    release: () => {},
  };
  const stripe: any = {
    prices: { retrieve: async () => price(priceMode) },
    customers: {
      retrieve: async (id: string) => { assert.equal(id, customer.id); return customer; },
      create: async (_params: any, options: any) => {
        assert.match(options.idempotencyKey, /^vata-live-customer-/);
        return customer;
      },
    },
    subscriptions: { list: async ({ customer: id }: any) => {
      assert.equal(id, customer.id);
      return { data: subscriptions };
    } },
    checkout: { sessions: {
      list: async ({ status }: any) => ({ data: status === 'open' ? open : [] }),
      create: async (params: any, options: any) => {
        assert.match(options.idempotencyKey, /^vata-live-checkout-/);
        created = params;
        return { url: sessionUrl, livemode: sessionMode };
      },
    } },
    billingPortal: {
      configurations: { list: async () => ({ data: [
        { id: 'bpc_test_fixture', metadata: { vata_portal: 'test_v1' } },
        { id: 'bpc_live_fixture', metadata: { vata_portal: 'live_v1' } },
      ] }) },
      sessions: { create: async (params: any) => { portal = params; return { url: 'https://billing.stripe.com/p/session/live_fixture' }; } },
    },
  };
  const router = createBillingRoutes({
    pool: { connect: async () => client } as any, requireOwner,
    billingStatus: async () => ({
      hasSubscription: paid, cancelAtPeriodEnd: false,
      plan: paid ? 'pro' : 'free', status: 'none', available: true, mode: 'live',
      testMode: false, checkoutReady: delivered, price: PRO_PRICE,
    }),
    checkedStripe: async () => { providerCalls++; return stripe; },
    proPrice: async () => 'price_live_fixture',
    appOrigin: () => 'https://vata.example.test',
    resolveBillingAccount: async account => ({ ...account, stripe_customer_id: liveCustomerId }),
    linkBillingCustomer: async (_client, _account, id) => { liveCustomerId = id; },
    withStripeSync: async (fn: any) => fn({ syncSingleEntity: async (id: string) => { synced.push(id); } }),
    assertCustomerOwnership,
  });
  const app = express();
  app.use(express.json());
  // Isolated offline fixture only. Never bypasses Clerk in the actual app.
  app.use((req: any, _res, next) => {
    req.account = { ...owner, role: req.get('x-fixture-role') ?? 'owner' };
    req.authMethod = req.get('x-fixture-auth') ?? 'session';
    next();
  });
  app.use('/api', router);
  app.use((error: any, _req: any, res: any, _next: any) =>
    res.status(error instanceof TierError ? error.status : 503).json({ error: error.message }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  async function request(path: string, headers: Record<string, string> = {}) {
    const response = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/api${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify({ price: 'price_attacker', success_url: 'https://evil.invalid', account_id: 99 }),
    });
    return { status: response.status, data: await response.json() };
  }
  assert.equal((await request('/checkout')).status, 503, 'No verified delivery, no live checkout.');
  assert.equal(providerCalls, 0);
  delivered = true;
  for (const path of ['/checkout', '/billing/portal', '/billing/refresh']) {
    assert.equal((await request(path, { 'x-fixture-role': 'member' })).status, 403);
    assert.equal((await request(path, { 'x-fixture-auth': 'api_key' })).status, 403);
  }
  assert.equal(providerCalls, 0);
  priceMode = false;
  assert.equal((await request('/checkout')).status, 503);
  priceMode = true;
  sessionMode = false;
  assert.equal((await request('/checkout')).status, 503);
  sessionMode = true;
  sessionUrl = 'https://evil.invalid/checkout';
  assert.equal((await request('/checkout')).status, 503);
  sessionUrl = 'https://checkout.stripe.com/c/pay/live_fixture';
  assert.equal((await request('/checkout')).status, 200);
  assert.equal(owner.stripe_customer_id, 'cus_legacy_test', 'Historical test link was not overwritten.');
  assert.equal(created.customer, 'cus_live_fixture');
  assert.deepEqual(created.line_items, [{ price: 'price_live_fixture', quantity: 1 }]);
  assert.equal(created.success_url, 'https://vata.example.test/user-portal?billing=success');
  assert.equal(created.subscription_data.metadata.clerk_user_id, owner.clerk_user_id);
  assert.equal((await request('/billing/portal')).status, 200);
  assert.equal(portal.configuration, 'bpc_live_fixture');
  assert.equal(portal.customer, 'cus_live_fixture');
  assert.equal((await request('/billing/refresh')).status, 200);
  assert.deepEqual(synced, ['cus_live_fixture']);
  open = [{ mode: 'subscription', livemode: false, url: sessionUrl, metadata }];
  assert.equal((await request('/checkout')).status, 409, 'Do not create duplicate checkouts for unverified open sessions.');
  open = [];
  subscriptions = [{ id: 'sub_live_fixture', status: 'past_due' }];
  assert.equal((await request('/checkout')).status, 409);
  subscriptions = [];
  paid = true;
  assert.equal((await request('/checkout')).status, 409);
});

test('signed live webhooks reject test/foreign events and reconcile cancellation, replay and retries', async () => {
  const restore = liveEnvironment();
  const stripe = new Stripe('sk_test_offline_signature_fixture');
  const secret = 'whsec_offline_synthetic_fixture_only';
  let deliveries = 0, reconciliations = 0, closed = 0, fail = false, canonical = 'active', mirrored = '';
  const receipts = new Map<string, any>();
  const runtime = async () => ({
    accountId: 'acct_live_fixture', endpoint: 'https://vata.example.test/api/stripe/webhook', mode: 'live' as const,
    verify: (payload: Buffer, signature: string) => stripe.webhooks.constructEventAsync(payload, signature, secret),
    sync: async () => ({
      processWebhook: async () => { deliveries++; },
      syncSingleEntity: async () => {
        if (fail) throw new Error('Synthetic canonical fetch failure');
        reconciliations++; mirrored = canonical;
      },
      postgresClient: { pool: { end: async () => { closed++; } } },
    }),
  });
  const process = createBillingWebhookProcessor(runtime, async (receipt, action) => {
    if (receipts.has(receipt.eventId)) return false;
    await action();
    receipts.set(receipt.eventId, receipt);
    return true;
  });
  function event(id: string, overrides: any = {}) {
    return { id, object: 'event', livemode: true, type: 'customer.subscription.updated',
      data: { object: { id: 'sub_live_fixture', status: canonical } }, ...overrides };
  }
  async function send(data: any, valid = true) {
    const payload = JSON.stringify(data);
    return process(Buffer.from(payload), valid
      ? stripe.webhooks.generateTestHeaderString({ payload, secret }) : 't=1,v1=forged');
  }
  try {
    const first = event('evt_livefirst');
    await assert.rejects(send(first, false));
    await assert.rejects(send(event('evt_wrongmode', { livemode: false })));
    await assert.rejects(send(event('evt_foreign', { account: 'acct_foreign' })));
    assert.equal(receipts.size, 0);
    await send(first);
    assert.equal(mirrored, 'active');
    await send(first);
    assert.equal(deliveries, 1, 'Authenticated duplicate is not processed again.');
    await assert.rejects(send(first, false), 'Duplicate IDs must still have valid signatures.');
    canonical = 'canceled';
    await send(event('evt_canceled', { type: 'customer.subscription.deleted' }));
    await send(event('evt_staleactive', { data: { object: { id: 'sub_live_fixture', status: 'active' } } }));
    assert.equal(mirrored, 'canceled', 'Old snapshots cannot resurrect a canceled subscription.');
    fail = true;
    await assert.rejects(send(event('evt_retry')));
    assert.equal(receipts.has('evt_retry'), false);
    fail = false;
    await send(event('evt_retry'));
    assert.equal(receipts.has('evt_retry'), true);
    await send(event('evt_catalog', { type: 'product.updated', data: { object: { id: 'prod_fixture' } } }));
    assert.equal(receipts.get('evt_catalog').livemode, true);
    assert.equal(receipts.get('evt_catalog').endpoint, 'https://vata.example.test/api/stripe/webhook');
    assert.ok(reconciliations >= 4);
    assert.equal(closed, deliveries + 1, 'SDK pools close even for duplicates and failed reconciliation.');
  } finally { restore(); }
});

test('billing receipt concurrency and failed actions are transactionally scoped to account/mode/endpoint', async () => {
  const prefix = `evt_receipt_${randomUUID().replaceAll('-', '')}`;
  const receipt = {
    accountId: 'acct_offline_receipt_fixture', livemode: true,
    endpoint: 'https://vata.example.test/api/stripe/webhook',
    eventId: prefix, eventType: 'product.updated', entity: 'prod_offline_fixture',
  };
  let executions = 0;
  try {
    const results = await Promise.all(Array.from({ length: 4 }, () =>
      oncePerBillingEvent(receipt, async () => { executions++; })));
    assert.equal(executions, 1);
    assert.equal(results.filter(Boolean).length, 1);
    await oncePerBillingEvent({ ...receipt, livemode: false }, async () => { executions++; });
    await oncePerBillingEvent({ ...receipt, endpoint: 'https://other.example.test/api/stripe/webhook' }, async () => { executions++; });
    assert.equal(executions, 3, 'Test/live and endpoint scopes are independent.');
    const retry = { ...receipt, eventId: `${prefix}_retry` };
    await assert.rejects(oncePerBillingEvent(retry, async () => { throw new Error('Synthetic failure'); }));
    assert.equal((await pool.query(
      'SELECT 1 FROM public.vata_billing_webhook_receipts WHERE event_id=$1', [retry.eventId],
    )).rowCount, 0);
    assert.equal(await oncePerBillingEvent(retry, async () => {}), true);
  } finally {
    await pool.query('DELETE FROM public.vata_billing_webhook_receipts WHERE event_id=ANY($1::text[])',
      [[prefix, `${prefix}_retry`]]);
    await pool.query('DELETE FROM public.vata_test_webhook_receipts WHERE event_id=$1',
      [`${JSON.stringify([receipt.accountId, receipt.endpoint])}:${prefix}`]);
    await pool.end();
  }
});
