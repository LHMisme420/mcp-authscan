import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';
import { assertSandboxContext, assertTestKey } from '../server/stripeSandbox';
import { TEST_LOOKUP_KEY, TestCheckoutService, validTestPrice } from '../server/testCheckoutService';
import { createTestCheckoutRoutes } from '../server/testCheckoutRoutes';

const account = { id: 42, clerk_user_id: 'test_owner_fixture', role: 'owner' };
const price = {
  id: 'price_fixture', lookup_key: TEST_LOOKUP_KEY, active: true, livemode: false,
  unit_amount: 9900, currency: 'usd', recurring: { interval: 'month', interval_count: 1 },
};
function fixture() {
  let session: any = {
    id: 'cs_test_fixture', url: 'https://checkout.stripe.com/c/pay/cs_test_fixture',
    livemode: false, client_reference_id: '42', status: 'open', payment_status: 'unpaid',
    metadata: { vata_account_id: '42', owner_user_id: account.clerk_user_id, purpose: 'vata_test_checkout' },
  };
  let created: any;
  let options: any;
  let clientCalls = 0;
  const service = new TestCheckoutService(async () => {
    clientCalls++;
    return { checkout: { sessions: {
      create: async (input: any, opts: any) => { created = input; options = opts; return session; },
      retrieve: async () => session,
      listLineItems: async () => ({ data: [{ quantity: 1, price: { id: price.id } }] }),
    } } } as any;
  }, async () => price, () => 'https://preview.example.test');
  return {
    service, setSession(value: any) { session = { ...session, ...value }; },
    get created() { return created; }, get options() { return options; }, get calls() { return clientCalls; },
  };
}

test('test keys and catalog are mandatory; live credentials/prices are rejected', () => {
  assert.doesNotThrow(() => assertTestKey('sk_test_fixture'));
  assert.doesNotThrow(() => assertTestKey('rk_test_fixture'));
  for (const key of ['sk_live_fixture', 'rk_live_fixture', undefined, 'invalid']) {
    assert.throws(() => assertTestKey(key), { status: 503 });
  }
  assert.throws(() => assertSandboxContext('production'), { status: 410 });
  assert.equal(validTestPrice(price), true);
  for (const patch of [{ livemode: true }, { unit_amount: 1 }, { currency: 'eur' },
    { recurring: { interval: 'year', interval_count: 1 } }, { lookup_key: 'other' }]) {
    assert.equal(validTestPrice({ ...price, ...patch }), false);
  }
});
test('production blocks service calls before contacting Stripe', async () => {
  const previous = process.env.NODE_ENV;
  const f = fixture();
  process.env.NODE_ENV = 'production';
  try {
    await assert.rejects(() => f.service.status(), { status: 410 });
    await assert.rejects(() => f.service.create(account, randomUUID()), { status: 410 });
    await assert.rejects(() => f.service.verify(account, 'cs_test_fixture'), { status: 410 });
    assert.equal(f.calls, 0);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});
test('checkout uses a real catalog price, server-owned metadata and scoped idempotency', async () => {
  const f = fixture();
  const requestId = randomUUID();
  const result = await f.service.create(account, requestId);
  assert.equal(result.mode, 'test');
  assert.deepEqual(f.created.line_items, [{ price: price.id, quantity: 1 }]);
  assert.equal(f.created.mode, 'subscription');
  assert.equal(f.created.client_reference_id, '42');
  assert.equal(f.created.metadata.owner_user_id, account.clerk_user_id);
  assert.equal(f.created.success_url, 'https://preview.example.test/user-portal?test_checkout_session={CHECKOUT_SESSION_ID}');
  assert.equal(f.options.idempotencyKey, `vata-test-checkout:42:${requestId}`);
});
test('redirects cannot confirm payment; Stripe status is checked and access is unchanged', async () => {
  const f = fixture();
  assert.equal((await f.service.verify(account, 'cs_test_fixture')).confirmed, false);
  f.setSession({ status: 'complete', payment_status: 'paid' });
  const result = await f.service.verify(account, 'cs_test_fixture');
  assert.equal(result.confirmed, true);
  assert.equal(result.accessChanged, false);
  f.setSession({ client_reference_id: 'another_account' });
  await assert.rejects(() => f.service.verify(account, 'cs_test_fixture'), { status: 403 });
});
test('unexpected live sessions and non-Stripe hosted URLs are rejected', async () => {
  const f = fixture();
  f.setSession({ livemode: true });
  await assert.rejects(() => f.service.create(account, randomUUID()), { status: 403 });
  f.setSession({ livemode: false, url: 'https://other.example.test' });
  await assert.rejects(() => f.service.create(account, randomUUID()), { status: 503 });
});
test('routes enforce owner/browser access and input validation', async () => {
  const f = fixture();
  const app = express();
  app.use(express.json());
  app.use((req: any, _res, next) => {
    req.account = { ...account, role: req.get('x-fixture-role') ?? 'owner' };
    req.authMethod = req.get('x-fixture-auth') ?? 'session';
    next();
  });
  app.use('/api', createTestCheckoutRoutes(f.service));
  app.use((error: any, _req: any, res: any, _next: any) => res.status(error.status ?? 500).json({ error: error.message }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const request = (path: string, method = 'GET', body?: any, headers = {}) =>
      fetch(`${origin}/api${path}`, { method, headers: { 'Content-Type': 'application/json', ...headers },
        body: body === undefined ? undefined : JSON.stringify(body) });
    assert.equal((await request('/test-checkout')).status, 200);
    assert.equal((await request('/test-checkout', 'GET', undefined, { 'x-fixture-role': 'member' })).status, 403);
    assert.equal((await request('/test-checkout', 'POST', {}, { 'x-fixture-auth': 'api_key' })).status, 403);
    assert.equal((await request('/checkout', 'POST', {})).status, 400);
    assert.equal((await request('/checkout', 'POST', { requestId: randomUUID() })).status, 201);
    assert.equal((await request('/test-checkout/cs_live_other')).status, 400);
  } finally {
    await new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve()));
  }
});
