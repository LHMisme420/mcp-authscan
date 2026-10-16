import { getUncachableStripeClient } from '../server/stripeClient';
import { billingStatus, initializeBilling } from '../server/billing';
import { pool } from '../server/db';
import { PRO_LOOKUP_KEY, PRO_PRICE } from '../server/billingPolicy';
import { readFile } from 'node:fs/promises';

if (process.env.NODE_ENV === 'production') throw new Error('Sandbox setup is Preview-only.');

try {
  const stripe = await getUncachableStripeClient();
  if ((await stripe.balance.retrieve()).livemode) throw new Error('Test mode required.');
  await pool.query(await readFile(new URL('../migrations/test-webhook-receipts.sql', import.meta.url), 'utf8'));
  const prices = await stripe.prices.list({ lookup_keys: [PRO_LOOKUP_KEY], limit: 1 });
  if (!prices.data.length) {
    const product = await stripe.products.create({
      name: 'VATA Pro',
      description: 'Programmatic API access, automated MCP scans, and up to five workspace seats.',
      metadata: { vata_plan: 'pro' },
    }, { idempotencyKey: 'vata-test-pro-product-v1' });
    await stripe.prices.create({
      product: product.id, unit_amount: PRO_PRICE.amount, currency: PRO_PRICE.currency,
      recurring: { interval: PRO_PRICE.interval }, lookup_key: PRO_LOOKUP_KEY,
    }, { idempotencyKey: 'vata-test-pro-usd-monthly-v1' });
  }
  const configurations = await stripe.billingPortal.configurations.list({ active: true, limit: 100 });
  if (!configurations.data.some(c => c.metadata?.vata_portal === 'test_v1')) {
    await stripe.billingPortal.configurations.create({
      business_profile: { headline: 'Manage your VATA Pro subscription' },
      metadata: { vata_portal: 'test_v1' },
      features: {
        customer_update: { enabled: false },
        invoice_history: { enabled: true },
        payment_method_update: { enabled: true },
        subscription_cancel: { enabled: true, mode: 'at_period_end' },
        subscription_update: { enabled: false },
      },
    }, { idempotencyKey: 'vata-test-portal-v1' });
  }
  console.info('Stripe test catalog and customer portal configured for $99 USD/month.');
  await initializeBilling();
  if (!(await billingStatus({ id: 0 })).available) throw new Error('Billing initialization did not complete.');
} catch {
  console.error('Stripe test setup failed. No live payments were enabled. Check the connected Stripe sandbox and billing database.');
  process.exitCode = 1;
} finally { await pool.end(); }
