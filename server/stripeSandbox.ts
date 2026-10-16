import { TierError } from './tiers';
import { getStripeSync, getUncachableStripeClient } from './stripeClient';

export function assertSandboxContext(environment = process.env.NODE_ENV) {
  if (environment === 'production') {
    throw new TierError(410, 'Test checkout is available in Preview only. Live payments are disabled.');
  }
}

export function assertTestKey(key: unknown): asserts key is string {
  if (typeof key !== 'string' || !/^(sk|rk)_test_[A-Za-z0-9]+$/.test(key)) {
    throw new TierError(503, 'A Stripe test connection is required. Live credentials cannot be used.');
  }
}

export async function getTestStripeClient() {
  assertSandboxContext();
  try {
    const stripe = await getUncachableStripeClient();
    if ((await stripe.balance.retrieve()).livemode) throw new TierError(503, 'A Stripe test connection is required.');
    return stripe;
  } catch (error) {
    if (error instanceof TierError) throw error;
    throw new TierError(503, 'Stripe test connection is unavailable. Scanning remains available.');
  }
}

export async function getTestStripeSync(webhookSecret = '') {
  assertSandboxContext();
  return getStripeSync(webhookSecret);
}
