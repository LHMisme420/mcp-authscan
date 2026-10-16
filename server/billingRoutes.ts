import { Router } from 'express';
import { createHash } from 'node:crypto';
import { pool } from './db';
import { requireOwner, TierError } from './tiers';
import { appOrigin } from './appOrigin';
import { assertCustomerOwnership, billingStatus, checkedStripe, proPrice, withStripeSync,
  resolveBillingAccount, linkBillingCustomer } from './billing';
import { billingMode, billingLivemode, stripeRedirect } from './billingMode';
import { subscriptionHasEnded, validProPrice } from './billingPolicy';

const defaultServices = {
  pool, requireOwner, billingStatus, checkedStripe, proPrice, withStripeSync, appOrigin, assertCustomerOwnership,
  resolveBillingAccount, linkBillingCustomer,
};
export function createBillingRoutes(services: Partial<typeof defaultServices> = {}) {
const { pool, requireOwner, billingStatus, checkedStripe, proPrice, withStripeSync, appOrigin, assertCustomerOwnership,
  resolveBillingAccount, linkBillingCustomer } = { ...defaultServices, ...services };
const billingRoutes = Router();
billingRoutes.use(['/checkout', '/billing'], (req: any, res, next) => {
  if (billingMode() === 'disabled') return res.status(410).json({ error: 'Payments are not enabled.' });
  if (req.method !== 'GET' && req.authMethod && req.authMethod !== 'session') {
    return res.status(403).json({ error: 'Manage billing from your signed-in browser, not an API token.' });
  }
  next();
});
billingRoutes.get('/billing/status', async (req: any, res) => {
  res.json(await billingStatus(req.account));
});

billingRoutes.post('/checkout', async (req: any, res, next) => {
  // Preserve the incoming standalone sandbox checkout's request-ID contract.
  if (req.body?.requestId !== undefined) return next('route');
  requireOwner(req.account);
  const status = await billingStatus(req.account);
  if (!status.available) throw new TierError(503, 'Checkout is temporarily unavailable. Basic scans remain available.');
  if (billingLivemode() && status.checkoutReady !== true) {
    throw new TierError(503, 'Live checkout is waiting for verified Stripe webhook delivery. No payment was started.');
  }
  if (status.plan === 'pro') throw new TierError(409, 'You already have Pro. Use Manage subscription.');
  const stripe = await checkedStripe();
  const price = await proPrice();
  if (!price) throw new TierError(503, 'The subscription price is not ready.');
  const priceObject = await stripe.prices.retrieve(price, { expand: ['product'] });
  if (!validProPrice(priceObject, billingLivemode())) throw new TierError(503, 'The verified $99/month price is unavailable.');
  const client = await pool.connect();
  let customerId: string;
  try {
    await client.query('BEGIN');
    const account = await resolveBillingAccount(
      (await client.query('SELECT * FROM public.vata_accounts WHERE id=$1 FOR UPDATE', [req.account.id])).rows[0]);
    customerId = account.stripe_customer_id;
    if (customerId) assertCustomerOwnership(await stripe.customers.retrieve(customerId), account);
    else {
      const customer = await stripe.customers.create({
        metadata: { vata_account_id: String(account.id), clerk_user_id: account.clerk_user_id },
      }, { idempotencyKey: `vata-${billingMode()}-customer-${account.id}-${account.clerk_user_id}` });
      assertCustomerOwnership(customer, account);
      customerId = customer.id;
      await linkBillingCustomer(client, account, customerId);
    }
    // Inspect Stripe itself as well as the mirror before permitting checkout.
    const subscriptions = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 100 });
    if (subscriptions.has_more) throw new TierError(503, 'Subscription history requires review before another checkout.');
    if (subscriptions.data.some(s => !subscriptionHasEnded(s.status))) {
      throw new TierError(409, 'A subscription already exists. Refresh billing or use Manage subscription.');
    }
    const open = await stripe.checkout.sessions.list({ customer: customerId, status: 'open', limit: 100 });
    if (open.has_more) throw new TierError(503, 'Open checkouts require review before another checkout.');
    const existing = open.data.find(s => s.mode === 'subscription' && s.livemode === billingLivemode() &&
      s.client_reference_id === String(account.id) && s.metadata?.vata_account_id === String(account.id) &&
      s.metadata?.clerk_user_id === account.clerk_user_id && s.metadata?.price_id === price);
    if (existing?.url) {
      const checkoutUrl = stripeRedirect(existing.url, 'checkout.stripe.com');
      await client.query('COMMIT');
      return res.json({ url: checkoutUrl });
    }
    if (open.data.length) throw new TierError(409, 'An earlier checkout is still open. Resolve it before starting another.');
    const fingerprint = createHash('sha256').update(JSON.stringify({
      customerId, price,
      subscriptions: subscriptions.data.map(s => s.id).sort(),
      sessions: (await stripe.checkout.sessions.list({ customer: customerId, limit: 100 })).data.map(s => `${s.id}:${s.status}`).sort(),
    })).digest('hex');
    const session = await stripe.checkout.sessions.create({
      customer: customerId, mode: 'subscription',
      line_items: [{ price, quantity: 1 }],
      client_reference_id: String(account.id),
      metadata: { vata_account_id: String(account.id), clerk_user_id: account.clerk_user_id, price_id: price },
      subscription_data: { metadata: { vata_account_id: String(account.id), clerk_user_id: account.clerk_user_id } },
      success_url: `${appOrigin()}/user-portal?billing=success`,
      cancel_url: `${appOrigin()}/user-portal?billing=cancelled`,
    }, { idempotencyKey: `vata-${billingMode()}-checkout-${fingerprint}` });
    if (session.livemode !== billingLivemode()) throw new TierError(503, 'Stripe returned a checkout in the wrong mode.');
    const checkoutUrl = stripeRedirect(session.url, 'checkout.stripe.com');
    await client.query('COMMIT');
    res.json({ url: checkoutUrl });
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
});

billingRoutes.post('/billing/portal', async (req: any, res) => {
  requireOwner(req.account);
  const stripe = await checkedStripe();
  const account = await resolveBillingAccount(req.account);
  if (!account.stripe_customer_id) throw new TierError(409, 'No subscription customer exists yet.');
  assertCustomerOwnership(await stripe.customers.retrieve(account.stripe_customer_id), account);
  const configurations = await stripe.billingPortal.configurations.list({ active: true, limit: 100 });
  const configuration = configurations.data.find(c => c.metadata?.vata_portal === `${billingMode()}_v1`);
  if (!configuration) throw new TierError(503, 'The billing portal is not configured.');
  const session = await stripe.billingPortal.sessions.create({
    customer: account.stripe_customer_id, configuration: configuration.id,
    return_url: `${appOrigin()}/user-portal`,
  });
  res.json({ url: stripeRedirect(session.url, 'billing.stripe.com') });
});

billingRoutes.post('/billing/refresh', async (req: any, res) => {
  requireOwner(req.account);
  const stripe = await checkedStripe();
  const account = await resolveBillingAccount(req.account);
  if (account.stripe_customer_id) {
    assertCustomerOwnership(await stripe.customers.retrieve(account.stripe_customer_id), account);
    await withStripeSync(async sync => {
      // Retrieve authoritative latest objects, never a return-URL flag.
      await sync.syncSingleEntity(account.stripe_customer_id);
      const subscriptions = await stripe.subscriptions.list({ customer: account.stripe_customer_id, status: 'all', limit: 100 });
      for (const subscription of subscriptions.data) await sync.syncSingleEntity(subscription.id);
    });
  }
  res.json(await billingStatus(req.account));
});
return billingRoutes;
}

export const billingRoutes = createBillingRoutes();
