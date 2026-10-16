import type Stripe from 'stripe';
import { pool } from './db';
import { appOrigin } from './appOrigin';
import { getStripeSync, getUncachableStripeClient } from './stripeClient';
import { assertStripeMode, billingMode } from './billingMode';
import { oncePerBillingEvent } from './billingWebhookReceipts';

export interface BillingWebhookRuntime {
  accountId: string;
  endpoint: string;
  mode: 'test' | 'live';
  verify(payload: Buffer, signature: string): Promise<Stripe.Event>;
  sync(): Promise<{
    processWebhook(payload: Buffer, signature: string): Promise<void>;
    syncSingleEntity(id: string): Promise<unknown>;
    postgresClient: { pool: { end(): Promise<void> } };
  }>;
}

async function managedRuntime(): Promise<BillingWebhookRuntime> {
  const mode = billingMode();
  if (mode === 'disabled') throw new Error('Billing is disabled.');
  const stripe = await getUncachableStripeClient();
  assertStripeMode((await stripe.balance.retrieve()).livemode, mode);
  const account = await stripe.accounts.retrieve(null);
  const endpoint = `${appOrigin()}/api/stripe/webhook`;
  const result = await pool.query(
    'SELECT secret FROM stripe._managed_webhooks WHERE account_id=$1 AND url=$2 LIMIT 1', [account.id, endpoint],
  );
  const secret = result.rows[0]?.secret;
  if (!secret) throw new Error('This exact billing callback is not configured.');
  return {
    accountId: account.id, endpoint, mode,
    verify: (payload, signature) => stripe.webhooks.constructEventAsync(payload, signature, secret),
    sync: () => getStripeSync(secret, mode),
  };
}

export function createBillingWebhookProcessor(
  runtime: () => Promise<BillingWebhookRuntime> = managedRuntime,
  once: typeof oncePerBillingEvent = oncePerBillingEvent,
) {
  return async (payload: Buffer, signature: string) => {
    if (billingMode() === 'disabled') throw new Error('Billing is disabled.');
    if (!Buffer.isBuffer(payload)) throw new Error('Webhook body must be raw bytes.');
    const active = await runtime();
    if (active.mode !== billingMode()) throw new Error('Webhook runtime mode mismatch.');
    // Always authenticate, including duplicate/replayed event IDs.
    const event = await active.verify(payload, signature);
    const object: any = event.data?.object;
    if (event.livemode !== (active.mode === 'live') || typeof event.type !== 'string' || !/^evt_[A-Za-z0-9]+$/.test(event.id) ||
        !object || typeof object !== 'object' || typeof object.id !== 'string' ||
        (event.account && event.account !== active.accountId)) {
      throw Object.assign(new Error('Invalid billing event.'), { type: 'StripeSignatureVerificationError' });
    }
    if (!/^(checkout\.session\.|customer\.subscription\.|invoice\.|product\.|price\.)/.test(event.type)) return;
    const subscription = event.type.startsWith('customer.subscription.') ? object.id
      : object.parent?.subscription_details?.subscription ?? object.subscription;
    const subscriptionId = typeof subscription === 'string' ? subscription : subscription?.id;
    const sync = await active.sync();
    try {
      await once({
        accountId: active.accountId, endpoint: active.endpoint, livemode: event.livemode,
        eventId: event.id, eventType: event.type, entity: subscriptionId ?? object.id,
      }, async () => {
        await sync.processWebhook(payload, signature);
        // Never let an out-of-order terminal snapshot resurrect a subscription.
        if (subscriptionId) await sync.syncSingleEntity(subscriptionId);
      });
    } finally { await sync.postgresClient.pool.end(); }
  };
}

const processWebhook = createBillingWebhookProcessor();
export class WebhookHandlers {
  static processWebhook = processWebhook;
}
