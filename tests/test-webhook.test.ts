import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Stripe from 'stripe';
import { createTestWebhookHandler } from '../server/testWebhook';
import { assertSandboxContext } from '../server/stripeSandbox';
import { TEST_LOOKUP_KEY, TestCheckoutService } from '../server/testCheckoutService';

test('signed test notifications reject forgery/live events and reconcile terminal states once', async () => {
  assertSandboxContext();
  const stripe = new Stripe('sk_test_fixture');
  const secret = 'whsec_unit_fixture_not_a_real_secret';
  let syncCalls = 0, refreshCalls = 0, closed = 0;
  let fail = false;
  const processed = new Set<string>();
  const app = express();
  app.post('/webhook', express.raw({ type: 'application/json' }), createTestWebhookHandler(async () => ({
    verify: (payload, signature) => stripe.webhooks.constructEventAsync(payload, signature, secret),
    subscriptionPurpose: async () => 'vata_test_checkout',
    sync: {
      processWebhook: async () => { syncCalls++; if (fail) throw new Error('fixture failure'); },
      syncSingleEntity: async id => { assert.equal(id, 'sub_fixture'); refreshCalls++; },
      postgresClient: { pool: { end: async () => { closed++; } } },
    },
  }), async (id, action) => {
    if (processed.has(id)) return false;
    await action(); processed.add(id); return true;
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const url = `http://127.0.0.1:${(server.address() as any).port}/webhook`;
  const event = {
    id: 'evt_fixture', type: 'customer.subscription.deleted', livemode: false,
    data: { object: { id: 'sub_fixture', status: 'canceled', metadata: { purpose: 'vata_test_checkout' } } },
  };
  async function send(body: any, signatureSecret: string | null = secret, timestamp?: number) {
    const payload = JSON.stringify(body);
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (signatureSecret) headers['stripe-signature'] = stripe.webhooks.generateTestHeaderString({
      payload, secret: signatureSecret, timestamp,
    });
    const res = await fetch(url, { method: 'POST', headers, body: payload });
    return { status: res.status, body: await res.json() as any };
  }
  try {
    assert.equal((await send(event, null)).status, 400);
    assert.equal((await send(event, 'wrong')).status, 400);
    assert.equal((await send(event, secret, Math.floor(Date.now() / 1000) - 900)).status, 400);
    assert.equal((await send({ ...event, livemode: true })).status, 400);
    const valid = await send(event);
    assert.equal(valid.status, 200);
    assert.equal(valid.body.accessChanged, false);
    assert.equal(refreshCalls, 1, 'Cancellation must be reconciled through Stripe, not just accepted from a snapshot.');
    assert.equal((await send(event)).body.duplicate, true);
    assert.equal(syncCalls, 1);
    assert.equal(refreshCalls, 1);
    assert.equal((await send(event, 'wrong')).status, 400, 'Replay still requires an authentic signature.');
    fail = true;
    assert.equal((await send({ ...event, id: 'evt_retry' })).status, 503);
    assert.equal(processed.has('evt_retry'), false);
    fail = false;
    assert.equal((await send({ ...event, id: 'evt_retry' })).status, 200);
    const ignored = await send({ ...event, id: 'evt_other', data: { object: { metadata: { purpose: 'other_app' } } } });
    assert.equal(ignored.body.ignored, true);
    assert.ok(closed > 0);
    const env = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      assert.equal((await send(event)).status, 410);
    } finally {
      if (env === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = env;
    }
  } finally {
    await new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve()));
  }
});

test('checkout verification reports current subscription state without granting paid access', async () => {
  const account = { id: 42, clerk_user_id: 'owner_fixture' };
  const price = { id: 'price_fixture', lookup_key: TEST_LOOKUP_KEY, active: true, livemode: false,
    unit_amount: 9900, currency: 'usd', recurring: { interval: 'month', interval_count: 1 } };
  let status = 'active', foreign = false, live = false;
  const service = new TestCheckoutService(async () => ({
    checkout: { sessions: {
      retrieve: async () => ({ id: 'cs_test_fixture', livemode: false, client_reference_id: '42',
        metadata: { purpose: 'vata_test_checkout', vata_account_id: '42', owner_user_id: 'owner_fixture' },
        status: 'complete', payment_status: 'paid', subscription: 'sub_fixture' }),
      listLineItems: async () => ({ data: [{ quantity: 1, price: { id: price.id } }] }),
    } },
    subscriptions: { retrieve: async () => ({ status, livemode: live, metadata: {
      purpose: 'vata_test_checkout', vata_account_id: foreign ? 'other' : '42',
    } }) },
  }) as any, async () => price);
  for (const value of ['active', 'past_due', 'canceled']) {
    status = value;
    const result = await service.verify(account, 'cs_test_fixture');
    assert.equal(result.subscriptionStatus, value);
    assert.equal(result.accessChanged, false);
  }
  foreign = true;
  await assert.rejects(service.verify(account, 'cs_test_fixture'), (e: any) => e.status === 403);
  foreign = false; live = true;
  await assert.rejects(service.verify(account, 'cs_test_fixture'), (e: any) => e.status === 403);
});
