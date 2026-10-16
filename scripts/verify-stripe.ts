import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { getUncachableStripeClient } from '../server/stripeClient';
import { initializeBilling, billingStatus, proPrice, withStripeSync } from '../server/billing';
import { pool } from '../server/db';
import { PRO_PRICE } from '../server/billingPolicy';

// Explicit opt-in synthetic sandbox check, never part of normal startup/CI.
if (process.env.NODE_ENV === 'production') throw new Error('Sandbox verification is development-only.');
let accountId: number | undefined;
let customerId: string | undefined;
let subscriptionId: string | undefined;
let checkoutId: string | undefined;
let stage = 'initialization';
const stripe = await getUncachableStripeClient();
try {
  assert.equal((await stripe.balance.retrieve()).livemode, false, 'Test mode required.');
  await initializeBilling();
  const price = await proPrice();
  assert.ok(price, 'Verified catalog price required.');
  const priceObject = await stripe.prices.retrieve(price);
  assert.equal(priceObject.unit_amount, PRO_PRICE.amount);
  assert.equal(priceObject.currency, PRO_PRICE.currency);
  assert.equal(priceObject.recurring?.interval, PRO_PRICE.interval);
  assert.equal(priceObject.livemode, false);
  const owner = `stripe_synthetic_${randomUUID()}`;
  const account = (await pool.query(
    'INSERT INTO public.vata_accounts(clerk_user_id) VALUES($1) RETURNING *', [owner],
  )).rows[0];
  accountId = account.id;
  const metadata = { vata_account_id: String(account.id), clerk_user_id: owner };
  stage = 'synthetic_customer';
  const paymentMethod = await stripe.paymentMethods.create({ type: 'card', card: { token: 'tok_visa' } });
  const customer = await stripe.customers.create({
    metadata, payment_method: paymentMethod.id, invoice_settings: { default_payment_method: paymentMethod.id },
  });
  customerId = customer.id;
  account.stripe_customer_id = customer.id;
  await pool.query('UPDATE public.vata_accounts SET stripe_customer_id=$1 WHERE id=$2', [customer.id, account.id]);
  assert.equal((await billingStatus(account)).plan, 'free');
  stage = 'checkout';
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription', customer: customer.id,
    line_items: [{ price, quantity: 1 }], subscription_data: { metadata },
    success_url: 'https://example.invalid/synthetic-success',
    cancel_url: 'https://example.invalid/synthetic-cancel',
  });
  checkoutId = session.id;
  assert.equal(session.livemode, false);
  assert.match(session.url!, /^https:\/\/checkout\.stripe\.com\//);
  assert.equal((await billingStatus(account)).plan, 'free', 'An unpaid checkout must not unlock Pro.');
  await stripe.checkout.sessions.expire(session.id);
  checkoutId = undefined;
  stage = 'test_subscription';
  const subscription = await stripe.subscriptions.create({
    customer: customer.id, items: [{ price }], metadata,
    default_payment_method: paymentMethod.id, payment_behavior: 'error_if_incomplete',
  });
  subscriptionId = subscription.id;
  assert.equal(subscription.status, 'active');
  await withStripeSync(async sync => {
    await sync.syncSingleEntity(customer.id);
    await sync.syncSingleEntity(subscription.id);
  });
  assert.equal((await billingStatus(account)).plan, 'pro');
  assert.equal((await billingStatus({ ...account, clerk_user_id: 'synthetic-other-owner' })).plan, 'free');
  stage = 'cancellation';
  await stripe.subscriptions.cancel(subscription.id);
  subscriptionId = undefined;
  await withStripeSync(sync => sync.syncSingleEntity(subscription.id));
  assert.equal((await billingStatus(account)).plan, 'free');
  console.info('Sandbox verification passed: fixed price, checkout, unpaid access denied, confirmed Pro, owner isolation, cancellation.');
} catch {
  console.error(`Sandbox verification failed (${stage}); no live payments were enabled.`);
  process.exitCode = 1;
} finally {
  let cleanupFailed = false;
  if (checkoutId) await stripe.checkout.sessions.expire(checkoutId).catch(() => { cleanupFailed = true; });
  if (subscriptionId) await stripe.subscriptions.cancel(subscriptionId).catch(() => { cleanupFailed = true; });
  if (customerId) await stripe.customers.del(customerId).catch(() => { cleanupFailed = true; });
  if (accountId) await pool.query('DELETE FROM public.vata_accounts WHERE id=$1', [accountId]).catch(() => { cleanupFailed = true; });
  await pool.end();
  if (cleanupFailed) {
    console.error('Synthetic test cleanup was incomplete. Review sandbox test records before retrying.');
    process.exitCode = 1;
  }
}
