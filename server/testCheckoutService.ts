import type Stripe from 'stripe';
import { pool } from './db';
import { appOrigin } from './appOrigin';
import { TierError } from './tiers';
import { assertSandboxContext, getTestStripeClient } from './stripeSandbox';

export const TEST_LOOKUP_KEY = 'vata_checkout_sandbox_monthly_99';
export const TEST_PRICE = { amount: 9900, currency: 'usd', interval: 'month' } as const;
type Owner = { id: number | string; clerk_user_id: string };
export function validTestPrice(price: any): boolean {
  return Boolean(price && price.livemode === false && price.active === true
    && price.lookup_key === TEST_LOOKUP_KEY && price.unit_amount === TEST_PRICE.amount
    && price.currency === TEST_PRICE.currency && price.recurring?.interval === TEST_PRICE.interval
    && price.recurring?.interval_count === 1);
}
export async function testCatalogPrice() {
  const result = await pool.query(
    'SELECT _raw_data FROM stripe.prices WHERE lookup_key=$1 AND active=true',
    [TEST_LOOKUP_KEY],
  );
  const price = result.rows.map(row => row._raw_data).find(validTestPrice);
  if (!price) throw new TierError(503, 'Test checkout is not prepared. Run checkout:prepare in the workspace.');
  return price;
}
export function assertOwnedTestSession(session: any, account: Owner) {
  if (!session || session.livemode !== false || !session.id?.startsWith('cs_test_')
    || session.client_reference_id !== String(account.id)
    || session.metadata?.vata_account_id !== String(account.id)
    || session.metadata?.owner_user_id !== account.clerk_user_id
    || session.metadata?.purpose !== 'vata_test_checkout') {
    throw new TierError(403, 'This test checkout does not belong to your workspace.');
  }
}
export class TestCheckoutService {
  constructor(
    private client: () => Promise<Stripe> = getTestStripeClient,
    private price: () => Promise<any> = testCatalogPrice,
    private origin: () => string = appOrigin,
  ) {}

  async status() {
    assertSandboxContext();
    await this.client(); // Validate fresh test credentials, not an old ready flag.
    const price = await this.price();
    if (!validTestPrice(price)) throw new TierError(503, 'Invalid test catalog price.');
    return { enabled: true, mode: 'test', price: TEST_PRICE };
  }
  async create(account: Owner, requestId: string) {
    assertSandboxContext();
    const stripe = await this.client();
    const price = await this.price();
    if (!validTestPrice(price)) throw new TierError(503, 'Invalid test catalog price.');
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      allowed_payment_method_types: ['card'],
      line_items: [{ price: price.id, quantity: 1 }],
      client_reference_id: String(account.id),
      metadata: { vata_account_id: String(account.id), owner_user_id: account.clerk_user_id, purpose: 'vata_test_checkout' },
      subscription_data: { metadata: { purpose: 'vata_test_checkout', vata_account_id: String(account.id), owner_user_id: account.clerk_user_id } },
      success_url: `${this.origin()}/user-portal?test_checkout_session={CHECKOUT_SESSION_ID}`,
      cancel_url: `${this.origin()}/user-portal?test_checkout_cancelled=1`,
      expires_at: Math.floor(Date.now() / 1000) + 1800,
    }, { idempotencyKey: `vata-test-checkout:${account.id}:${requestId}` });
    assertOwnedTestSession(session, account);
    const url = new URL(session.url ?? '');
    if (url.protocol !== 'https:' || url.hostname !== 'checkout.stripe.com') {
      throw new TierError(503, 'Stripe did not return a valid hosted checkout URL.');
    }
    return { sessionId: session.id, checkout_url: session.url, mode: 'test' };
  }
  async verify(account: Owner, sessionId: string) {
    assertSandboxContext();
    const stripe = await this.client();
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    assertOwnedTestSession(session, account);
    const lines = await stripe.checkout.sessions.listLineItems(sessionId, { limit: 2 });
    const price = await this.price();
    const validItems = lines.data.length === 1 && lines.data[0].quantity === 1
      && lines.data[0].price?.id === price.id && validTestPrice(price);
    let subscriptionStatus: string | null = null;
    if (session.subscription) {
      const id = typeof session.subscription === 'string' ? session.subscription : session.subscription.id;
      const subscription = await stripe.subscriptions.retrieve(id);
      if (subscription.livemode !== false || subscription.metadata.purpose !== 'vata_test_checkout'
        || subscription.metadata.vata_account_id !== String(account.id)) {
        throw new TierError(403, 'This test subscription does not belong to your workspace.');
      }
      subscriptionStatus = subscription.status;
    }
    return {
      sessionId, mode: 'test', status: session.status, paymentStatus: session.payment_status,
      confirmed: validItems && session.status === 'complete' && session.payment_status === 'paid',
      accessChanged: false,
      subscriptionStatus,
    };
  }
}
