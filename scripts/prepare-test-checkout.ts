import { runMigrations } from 'stripe-replit-sync';
import { readFile } from 'node:fs/promises';
import { pool } from '../server/db';
import { assertSandboxContext, getTestStripeClient, getTestStripeSync } from '../server/stripeSandbox';
import { TEST_LOOKUP_KEY, testCatalogPrice, validTestPrice } from '../server/testCheckoutService';

assertSandboxContext();
const stripe = await getTestStripeClient(); // Guard test credentials before ANY write.
const existing = await stripe.prices.list({ lookup_keys: [TEST_LOOKUP_KEY], active: true, limit: 10 });
let price = existing.data.find(validTestPrice);
if (existing.data.length && !price) throw new Error('A conflicting sandbox price exists. No changes were made.');
if (!price) {
  const product = await stripe.products.create({
    name: 'VATA — test checkout only',
    description: 'Sandbox subscription. No real charges or changes to workspace access.',
    metadata: { app: 'vata', purpose: 'test_checkout' },
  }, { idempotencyKey: 'vata-test-checkout-product' });
  if (product.livemode) throw new Error('Unexpected live product; refusing to continue.');
  price = await stripe.prices.create({
    product: product.id, currency: 'usd', unit_amount: 9900,
    recurring: { interval: 'month' }, lookup_key: TEST_LOOKUP_KEY,
    metadata: { purpose: 'test_checkout' },
  }, { idempotencyKey: 'vata-test-checkout-monthly-price' });
}
if (!validTestPrice(price)) throw new Error('Sandbox price validation failed.');
// Explicit development preparation only; never a startup/readiness dependency.
await runMigrations({ databaseUrl: process.env.DATABASE_URL! });
await pool.query(await readFile(new URL('../migrations/test-webhook-receipts.sql', import.meta.url), 'utf8'));
const sync = await getTestStripeSync();
try {
  await sync.syncSingleEntity(typeof price.product === 'string' ? price.product : price.product.id);
  await sync.syncSingleEntity(price.id);
  await testCatalogPrice();
  console.log('Stripe TEST catalog prepared: $99 USD/month. No access restrictions were enabled.');
} finally {
  await sync.postgresClient.pool.end();
  await pool.end();
}
