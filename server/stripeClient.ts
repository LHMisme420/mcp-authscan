import Stripe from 'stripe';
import { StripeSync } from 'stripe-replit-sync';
import { ReplitConnectors } from '@replit/connectors-sdk';
import { assertStripeMode } from './billingMode';

class ConnectorStripeSync extends StripeSync {
  override async syncPaymentMethods() {
    // The library's stock method enumerates mirror customers without an
    // account_id filter. Old connector accounts must never enter this request.
    const accountId = await this.getAccountId();
    let synced = 0;
    for await (const customer of this.stripe.customers.list({ limit: 100 })) {
      for await (const method of this.stripe.paymentMethods.list({ customer: customer.id, limit: 100 })) {
        await this.upsertPaymentMethods([method], accountId);
        synced++;
      }
    }
    return { synced };
  }
}

// This connector authenticates through a proxy, not exportable API keys.
// A fresh transport lets the connector handle identity and credential rotation.
export async function getUncachableStripeClient() {
  const proxyFetch = new ReplitConnectors().createProxyFetch('stripe');
  return new Stripe('', {
    authenticator: async () => {},
    httpClient: Stripe.createFetchHttpClient(proxyFetch),
    timeout: 10000,
    maxNetworkRetries: 1,
  });
}

export async function getStripeSync(webhookSecret = '', mode: 'test' | 'live' = 'test') {
  if (!process.env.DATABASE_URL) throw new Error('Billing storage is unavailable.');
  const stripe = await getUncachableStripeClient();
  const [account, balance] = await Promise.all([stripe.accounts.retrieve(null), stripe.balance.retrieve()]);
  assertStripeMode(balance.livemode, mode);
  const sync = new ConnectorStripeSync({
    poolConfig: { connectionString: process.env.DATABASE_URL, max: 2, connectionTimeoutMillis: 3000 },
    // The library hashes this transport identifier for its account cache.
    // It is NOT an API key and is never sent to Stripe: replace its public
    // transport before any library operation with the authenticated SDK above.
    stripeSecretKey: `connector:${account.id}:${mode}`,
    stripeAccountId: account.id,
    stripeWebhookSecret: webhookSecret,
    backfillRelatedEntities: true,
    revalidateObjectsViaStripeApi: ['subscription', 'invoice'],
    logger: {
      info: () => {},
      warn: () => console.warn('Stripe synchronization warning.'),
      error: () => console.error('Stripe synchronization failed.'),
    },
  });
  sync.stripe = stripe;
  return sync;
}
