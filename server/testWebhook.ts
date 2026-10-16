import type Stripe from 'stripe';
import type { RequestHandler } from 'express';
import { pool } from './db';
import { assertSandboxContext, getTestStripeClient, getTestStripeSync } from './stripeSandbox';
import { TierError } from './tiers';
import { appOrigin } from './appOrigin';

export interface TestWebhookRuntime {
  verify(payload: Buffer, signature: string): Promise<Stripe.Event>;
  subscriptionPurpose?(id: string): Promise<string | undefined>;
  sync: {
    processWebhook(payload: Buffer, signature: string): Promise<void>;
    syncSingleEntity(id: string): Promise<unknown>;
    postgresClient: { pool: { end(): Promise<void> } };
  };
}
async function managedRuntime(): Promise<TestWebhookRuntime> {
  const stripe = await getTestStripeClient();
  const account = await stripe.accounts.retrieve(null);
  // Managed by stripe-replit-sync, never supplied by a browser or request body.
  const result = await pool.query(
    'SELECT secret FROM stripe._managed_webhooks WHERE account_id=$1 AND url=$2 LIMIT 1',
    [account.id, `${appOrigin()}/api/test-checkout/webhook`],
  );
  const secret = result.rows[0]?.secret;
  if (!secret) throw new TierError(503, 'Test webhook delivery is not configured. Keep live billing disabled.');
  const sync = await getTestStripeSync(secret);
  return {
    verify: (payload, signature) => stripe.webhooks.constructEventAsync(payload, signature, secret),
    subscriptionPurpose: async id => {
      const subscription = await stripe.subscriptions.retrieve(id);
      return subscription.livemode === false ? subscription.metadata.purpose : undefined;
    },
    sync,
  };
}

export async function oncePerTestEvent(id: string, action: () => Promise<void>, entity = id) {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    await db.query('SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))', ['vata-test-webhook', id]);
    await db.query('SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))', ['vata-test-entity', entity]);
    const prior = await db.query('SELECT 1 FROM public.vata_test_webhook_receipts WHERE event_id=$1', [id]);
    if (prior.rowCount) { await db.query('COMMIT'); return false; }
    await action();
    await db.query('INSERT INTO public.vata_test_webhook_receipts(event_id) VALUES ($1)', [id]);
    await db.query('COMMIT');
    return true;
  } catch (error) {
    await db.query('ROLLBACK');
    throw error;
  } finally { db.release(); }
}

export function createTestWebhookHandler(
  runtime: () => Promise<TestWebhookRuntime> = managedRuntime,
  once: typeof oncePerTestEvent = oncePerTestEvent,
): RequestHandler {
  return async (req, res) => {
    let active: TestWebhookRuntime | undefined;
    try {
      assertSandboxContext();
      const signature = req.headers['stripe-signature'];
      if (!Buffer.isBuffer(req.body) || typeof signature !== 'string') {
        return void res.status(400).json({ error: 'A raw, signed Stripe test notification is required.' });
      }
      active = await runtime();
      const event = await active.verify(req.body, signature);
      if (event.livemode !== false || typeof event.type !== 'string'
        || !event.data?.object || typeof event.data.object !== 'object'
        || !/^evt_[A-Za-z0-9]+$/.test(event.id)) {
        return void res.status(400).json({ error: 'Only Stripe test events are accepted.' });
      }
      const object = event.data.object as any;
      const subscription = event.type.startsWith('customer.subscription.') ? object.id
        : object.parent?.subscription_details?.subscription ?? object.subscription;
      const subscriptionId = typeof subscription === 'string' ? subscription : subscription?.id;
      let purpose = object.metadata?.purpose
        ?? object.parent?.subscription_details?.metadata?.purpose
        ?? object.subscription_details?.metadata?.purpose;
      if (!purpose && event.type.startsWith('invoice.')) {
        if (subscriptionId && active.subscriptionPurpose) purpose = await active.subscriptionPurpose(subscriptionId);
      }
      const supported = /^(checkout\.session\.|customer\.subscription\.|invoice\.)/.test(event.type);
      if (!supported || purpose !== 'vata_test_checkout') {
        return void res.json({ received: true, ignored: true, mode: 'test', accessChanged: false });
      }
      const sync = active.sync;
      const processed = await once(event.id, async () => {
        await sync.processWebhook(req.body, signature);
        // Terminal snapshots can bypass SDK revalidation and have coarse event
        // timestamps. Reconcile the canonical current state before acknowledging.
        if (subscriptionId) await sync.syncSingleEntity(subscriptionId);
      }, subscriptionId ?? object.id);
      res.json({ received: true, duplicate: !processed, mode: 'test', accessChanged: false });
    } catch (error: any) {
      const status = error instanceof TierError ? error.status
        : error?.type === 'StripeSignatureVerificationError' ? 400 : 503;
      res.status(status).json({ error: status === 410 ? 'Live billing is disabled.'
        : status === 400 ? 'Invalid Stripe signature or payload.'
        : 'Test notification processing is unavailable. Delivery must be configured before live billing.' });
    } finally {
      if (active) await active.sync.postgresClient.pool.end();
    }
  };
}
