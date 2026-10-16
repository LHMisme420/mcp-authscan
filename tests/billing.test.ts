import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { PRO_LOOKUP_KEY, PRO_PRICE, subscriptionGrantsAccess, subscriptionBillingState } from '../server/billingPolicy';
import { assertCustomerOwnership, billingStatus, initializeBilling, requirePro } from '../server/billing';
import { createBillingRoutes } from '../server/billingRoutes';
import { requireOwner, TierError } from '../server/tiers';

const account = { id: 123, clerk_user_id: 'synthetic-owner', stripe_customer_id: 'cus_fixture', role: 'owner' };
const customer = { id: 'cus_fixture', livemode: false, metadata: { vata_account_id: '123', clerk_user_id: 'synthetic-owner' } };
const subscription = {
  id: 'sub_fixture', livemode: false, status: 'active', customer: 'cus_fixture',
  metadata: customer.metadata,
  items: { data: [{ price: { id: 'price_fixture' }, current_period_end: 2000000000 }] },
};

test('only verified, unexpired, correct-owner test subscriptions grant Pro', () => {
  const now = 1800000000000;
  assert.equal(subscriptionGrantsAccess(subscription, 'price_fixture', account, now), true);
  for (const status of ['trialing', 'past_due', 'unpaid', 'incomplete', 'incomplete_expired', 'paused', 'canceled']) {
    assert.equal(subscriptionGrantsAccess({ ...subscription, status }, 'price_fixture', account, now), false, status);
  }
  assert.equal(subscriptionGrantsAccess(subscription, 'price_other', account, now), false);
  assert.equal(subscriptionGrantsAccess(subscription, 'price_fixture', { ...account, id: 124 }, now), false);
  assert.equal(subscriptionGrantsAccess(subscription, 'price_fixture', { ...account, clerk_user_id: 'different-owner' }, now), false);
  assert.equal(subscriptionGrantsAccess(subscription, 'price_fixture', { ...account, stripe_customer_id: 'cus_other' }, now), false);
  assert.equal(subscriptionGrantsAccess({ ...subscription, livemode: true }, 'price_fixture', account, now), false);
  assert.equal(subscriptionGrantsAccess(subscription, 'price_fixture', account, 2000000000000), false);
  assert.equal(subscriptionGrantsAccess({ subscription_tier: 'pro', success: true }, 'price_fixture', account, now), false);
});

test('legacy customers cannot be claimed by matching account names or IDs', () => {
  assert.doesNotThrow(() => assertCustomerOwnership(customer, account));
  for (const candidate of [
    { ...customer, deleted: true }, { ...customer, livemode: true }, { ...customer, metadata: {} },
    { ...customer, metadata: { ...customer.metadata, clerk_user_id: 'someone-else' } },
  ]) assert.throws(() => assertCustomerOwnership(candidate, account), (e: any) => e.status === 409);
});

test('SDK subscription state distinguishes recovery, cancellation and new Free workspaces without granting access', () => {
  const state = (rows: any[]) => subscriptionBillingState(rows, 'price_fixture', account, false);
  assert.deepEqual(state([]), { plan: 'free', status: 'none', hasSubscription: false, cancelAtPeriodEnd: false });
  for (const status of ['past_due', 'unpaid', 'incomplete', 'paused', 'trialing']) {
    const result = state([{ ...subscription, status }]);
    assert.equal(result.status, status);
    assert.equal(result.plan, 'free');
    assert.equal(result.hasSubscription, true);
    // A newer ended subscription must not hide an existing recoverable one.
    assert.equal(state([{ ...subscription, status: 'canceled' }, { ...subscription, status }]).status, status);
  }
  for (const status of ['canceled', 'incomplete_expired']) {
    assert.equal(state([{ ...subscription, status }]).hasSubscription, false);
  }
  const ending = state([{ ...subscription, cancel_at_period_end: true }]);
  assert.equal(ending.plan, 'pro');
  assert.equal(ending.cancelAtPeriodEnd, true);
  for (const foreign of [
    { ...subscription, livemode: true },
    { ...subscription, customer: 'cus_other' },
    { ...subscription, metadata: { ...customer.metadata, vata_account_id: '456' } },
    { ...subscription, metadata: { ...customer.metadata, clerk_user_id: 'other-owner' } },
  ]) assert.throws(() => state([foreign]), /ownership/);
  assert.equal(subscriptionBillingState([{ ...subscription, livemode: true }], 'price_fixture', account, true).plan, 'pro');
});

test('billing outage fails paid access closed without blocking account summary', async () => {
  const status = await billingStatus(account);
  assert.equal(status.available, false);
  assert.equal(status.plan, 'free');
  await assert.rejects(requirePro(account), (e: any) => e.status === 503);
});

test('production skips Stripe initialization and retains subscription-free access', async () => {
  const previous = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  try {
    await initializeBilling();
    await assert.doesNotReject(requirePro(account));
    const status = await billingStatus(account);
    assert.equal(status.status, 'disabled');
    assert.equal(status.available, false);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test('checkout, refresh and portal enforce owner, fixed price, ownership and safe returns', async t => {
  let unavailable = false, paid = false, providerCalls = 0, sessionCreated = 0, linked = false;
  let openSession: any = null;
  let subscriptions: any[] = [];
  let sessionParams: any, portalParams: any;
  const fakeAccount = { ...account, stripe_customer_id: null as string | null };
  const stripe = {
    customers: {
      create: async () => { providerCalls++; return customer; },
      retrieve: async () => customer,
    },
    prices: { retrieve: async () => ({
      id: 'price_fixture', livemode: false, active: true, lookup_key: PRO_LOOKUP_KEY,
      currency: 'usd', unit_amount: 9900, recurring: { interval: 'month', interval_count: 1 },
      product: { active: true, livemode: false, metadata: { vata_plan: 'pro' } },
    }) },
    subscriptions: { list: async () => ({ data: subscriptions }) },
    checkout: { sessions: {
      list: async (params: any) => ({ data: params.status === 'open' && openSession ? [openSession] : [] }),
      create: async (params: any, options: any) => {
        assert.match(options.idempotencyKey, /^vata-test-checkout-/);
        sessionCreated++; sessionParams = params;
        return { url: 'https://checkout.stripe.com/c/pay/synthetic', livemode: false };
      },
    } },
    billingPortal: {
      configurations: { list: async () => ({ data: [{ id: 'bpc_fixture', metadata: { vata_portal: 'test_v1' } }] }) },
      sessions: { create: async (params: any) => { portalParams = params; return { url: 'https://billing.stripe.com/p/session/synthetic' }; } },
    },
  };
  const synced: string[] = [];
  const client = {
    query: async (sql: string) => {
      if (sql.startsWith('SELECT *')) return { rows: [{ ...fakeAccount }] };
      if (sql.startsWith('UPDATE')) { fakeAccount.stripe_customer_id = customer.id; linked = true; }
      return { rows: [] };
    }, release: () => {},
  };
  const router = createBillingRoutes({
    pool: { connect: async () => client } as any,
    requireOwner,
    billingStatus: async () => ({ plan: paid ? 'pro' : 'free', status: 'none', available: !unavailable,
      hasSubscription: paid, cancelAtPeriodEnd: false,
      mode: 'test' as const, checkoutReady: true, testMode: true, price: PRO_PRICE }),
    checkedStripe: async () => { providerCalls++; return stripe as any; },
    proPrice: async () => 'price_fixture',
    withStripeSync: async (fn: any) => fn({ syncSingleEntity: async (id: string) => { synced.push(id); } }),
    appOrigin: () => 'https://vata.example.test',
    assertCustomerOwnership,
  });
  const app = express();
  app.use(express.json());
  // Offline HTTP fixture only; the real application always uses Clerk.
  app.use((req: any, res, next) => {
    const role = req.get('x-fixture-role');
    if (!role) return res.status(401).json({ error: 'Unauthorized' });
    req.account = { ...fakeAccount, role };
    next();
  });
  app.use('/api', router);
  app.use((e: any, _req: any, res: any, _next: any) => res.status(e instanceof TierError ? e.status : 503).json({ error: e.message }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve())));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  async function request(endpoint: string, role = 'owner', body: any = {}) {
    const response = await fetch(`${origin}/api${endpoint}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...(role ? { 'x-fixture-role': role } : {}) },
      body: JSON.stringify(body),
    });
    return { status: response.status, data: await response.json() };
  }
  assert.equal((await request('/checkout', '')).status, 401);
  for (const endpoint of ['/checkout', '/billing/portal', '/billing/refresh']) {
    assert.equal((await request(endpoint, 'member')).status, 403);
  }
  assert.equal(providerCalls, 0);
  unavailable = true;
  assert.equal((await request('/checkout')).status, 503);
  unavailable = false;
  assert.equal((await request('/checkout', 'owner', { price: 'price_attacker', account_id: 99, success_url: 'https://evil.invalid' })).status, 200);
  assert.equal(linked, true);
  assert.deepEqual(sessionParams.line_items, [{ price: 'price_fixture', quantity: 1 }]);
  assert.equal(sessionParams.success_url, 'https://vata.example.test/user-portal?billing=success');
  assert.equal(sessionParams.cancel_url, 'https://vata.example.test/user-portal?billing=cancelled');
  assert.deepEqual(sessionParams.subscription_data.metadata, customer.metadata);
  openSession = { url: 'https://checkout.stripe.com/c/pay/existing', mode: 'subscription', livemode: false,
    client_reference_id: '123', metadata: { vata_account_id: '123', clerk_user_id: 'synthetic-owner', price_id: 'price_fixture' } };
  assert.equal((await request('/checkout')).data.url, openSession.url);
  assert.equal(sessionCreated, 1, 'an existing open checkout is reused');
  openSession = null; subscriptions = [subscription];
  assert.equal((await request('/checkout')).status, 409);
  for (const status of ['past_due', 'unpaid', 'incomplete', 'paused']) {
    subscriptions = [{ ...subscription, status }];
    assert.equal((await request('/checkout')).status, 409, `${status} cannot start a duplicate checkout`);
  }
  assert.equal(sessionCreated, 1);
  assert.equal((await request('/billing/refresh')).status, 200);
  assert.deepEqual(synced, ['cus_fixture', 'sub_fixture']);
  assert.equal((await request('/billing/portal')).status, 200);
  assert.equal(portalParams.customer, 'cus_fixture');
  assert.equal(portalParams.return_url, 'https://vata.example.test/user-portal');
  paid = true;
  assert.equal((await request('/checkout')).status, 409);
});
