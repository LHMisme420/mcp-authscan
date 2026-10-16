import { runMigrations } from 'stripe-replit-sync';
import { pool } from './db';
import { TierError } from './tiers';
import { getStripeSync, getUncachableStripeClient } from './stripeClient';
import { PRO_LOOKUP_KEY, PRO_PRICE, subscriptionBillingState } from './billingPolicy';
import { billingMode, billingLivemode, assertStripeMode } from './billingMode';
import { appOrigin } from './appOrigin';

let ready = false;
let stripeAccountId: string | undefined;
let initializing: Promise<void> | undefined;

export function advancedBillingEnabled() {
  return billingMode() !== 'disabled';
}

export async function withStripeSync<T>(work: (sync: Awaited<ReturnType<typeof getStripeSync>>) => Promise<T>) {
  const mode = billingMode();
  if (mode === 'disabled') throw new Error('Billing is disabled.');
  const sync = await getStripeSync('', mode);
  try { return await work(sync); }
  finally { await sync.postgresClient.pool.end(); }
}

/** Optional dependency: never delays gateway startup, sign-in, or free scans. */
export function initializeBilling() {
  if (!advancedBillingEnabled()) return Promise.resolve();
  if (initializing) return initializing;
  initializing = (async () => {
    ready = false;
    let stage = 'connection';
    try {
      if (!process.env.DATABASE_URL) throw new Error('No billing database.');
      if (!process.env.REPLIT_CONNECTORS_HOSTNAME ||
          (!process.env.REPL_IDENTITY && !process.env.WEB_REPL_RENEWAL)) return;
      const stripe = await getUncachableStripeClient();
      const mode = billingMode();
      if (mode === 'disabled') return;
      assertStripeMode((await stripe.balance.retrieve()).livemode, mode);
      // Library-owned stripe schema only. No application schema migrations.
      stage = 'billing_schema';
      await runMigrations({ databaseUrl: process.env.DATABASE_URL });
      stage = 'sync_connection';
      await withStripeSync(async sync => {
        stripeAccountId = await sync.getAccountId();
        // Do not register, enable or replace callbacks during startup. A separate
        // scoped setup must preserve existing endpoints and disabled test hooks.
        stage = 'backfill';
        await sync.syncBackfill({ object: 'all' });
      });
      ready = true;
      console.info(`Stripe ${mode} billing synchronization is ready.`);
    } catch {
      console.warn(`Stripe billing unavailable (${stage}); sign-in and free scans remain available.`);
      const retry = setTimeout(() => { void initializeBilling(); }, 60000);
      retry.unref();
    } finally { initializing = undefined; }
  })();
  return initializing;
}

export async function proPrice() {
  if (!ready || !stripeAccountId) return null;
  const result = await pool.query(
    `SELECT p.id FROM stripe.prices p JOIN stripe.products product
     ON product.id=p.product AND product._account_id=p._account_id
      WHERE p._account_id=$1 AND p.lookup_key=$2 AND p.active=true AND p.livemode=$3
       AND p.currency='usd' AND p.unit_amount=9900 AND p.recurring->>'interval'='month'
       AND (p.recurring->>'interval_count')::int=1 AND product.active=true
        AND product.livemode=$3 AND product.metadata->>'vata_plan'='pro' LIMIT 1`,
    [stripeAccountId, PRO_LOOKUP_KEY, billingLivemode()],
  );
  return result.rows[0]?.id as string | undefined ?? null;
}

export async function billingStatus(account: any) {
  const mode = billingMode();
  const unavailable = { plan: 'free' as const, status: 'unavailable', available: false, mode,
    testMode: mode === 'test', checkoutReady: false, price: null };
  if (!advancedBillingEnabled()) return { ...unavailable, status: 'disabled' };
  if (!ready) return unavailable;
  try {
    const priceId = await proPrice();
    if (!priceId) return unavailable;
    const billingAccount = await resolveBillingAccount(account);
    const subscriptions = billingAccount.stripe_customer_id ? (await pool.query(
      'SELECT _raw_data FROM stripe.subscriptions WHERE _account_id=$1 AND customer=$2 AND livemode=$3 ORDER BY created DESC',
      [stripeAccountId, billingAccount.stripe_customer_id, billingLivemode()],
    )).rows.map(row => row._raw_data) : [];
    const subscriptionState = subscriptionBillingState(subscriptions, priceId, billingAccount, billingLivemode());
    // Existing subscribers can retain verified access while checkout is closed.
    // A real signed catalog delivery must arrive before the first live checkout.
    const deliveryVerified = mode !== 'live' || await liveDeliveryVerified();
    return {
      ...subscriptionState,
      available: true, checkoutReady: deliveryVerified, mode, testMode: mode === 'test', price: PRO_PRICE,
    };
  } catch { return unavailable; }
}

export async function requirePro(account: any) {
  // Production remains subscription-free unless explicitly opted into live mode.
  if (!advancedBillingEnabled()) return;
  const status = await billingStatus(account);
  if (!status.available) throw new TierError(503, 'Subscription verification is temporarily unavailable. Basic scans remain available.');
  if (status.plan !== 'pro') throw new TierError(403, 'VATA Pro ($99 USD/month) is required for API access, scheduling, and team features.');
}

export async function checkedStripe() {
  const stripe = await getUncachableStripeClient();
  const [balance, account] = await Promise.all([stripe.balance.retrieve(), stripe.accounts.retrieve(null)]);
  if (billingMode() === 'disabled' || balance.livemode !== billingLivemode() || account.id !== stripeAccountId ||
      (billingLivemode() && !account.charges_enabled)) {
    ready = false;
    throw new TierError(503, 'Stripe connection does not match the configured billing account and mode.');
  }
  return stripe;
}

export function assertCustomerOwnership(customer: any, account: any) {
  if (customer.deleted || customer.livemode !== billingLivemode() ||
      customer.metadata?.vata_account_id !== String(account.id) ||
      customer.metadata?.clerk_user_id !== account.clerk_user_id) {
    throw new TierError(409, 'Billing ownership needs verification. Contact the workspace owner; historical subscriptions are not claimed automatically.');
  }
}

/** Never overwrite a sandbox/legacy customer link with a live customer. */
export async function resolveBillingAccount(account: any) {
  if (!billingLivemode()) return account;
  if (!stripeAccountId) throw new Error('Billing account is not ready.');
  const result = await pool.query(
    `SELECT customer_id FROM public.vata_billing_customers
     WHERE account_id=$1 AND stripe_account_id=$2 AND livemode=true`, [account.id, stripeAccountId],
  );
  return { ...account, stripe_customer_id: result.rows[0]?.customer_id ?? null };
}

export async function linkBillingCustomer(client: any, account: any, customerId: string) {
  if (!billingLivemode()) {
    await client.query('UPDATE public.vata_accounts SET stripe_customer_id=$1 WHERE id=$2', [customerId, account.id]);
    return;
  }
  if (!stripeAccountId) throw new Error('Billing account is not ready.');
  await client.query(
    `INSERT INTO public.vata_billing_customers(account_id,stripe_account_id,livemode,customer_id)
     VALUES($1,$2,true,$3)`, [account.id, stripeAccountId, customerId],
  );
}

async function liveDeliveryVerified() {
  const result = await pool.query(
    `SELECT 1 FROM public.vata_billing_webhook_receipts
     WHERE stripe_account_id=$1 AND livemode=true AND endpoint_url=$2
       AND event_type IN ('product.created','product.updated','price.created','price.updated')
     LIMIT 1`, [stripeAccountId, `${appOrigin()}/api/stripe/webhook`],
  );
  return !!result.rowCount;
}
