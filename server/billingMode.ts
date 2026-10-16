export type BillingMode = 'disabled' | 'test' | 'live';

/** Payments require explicit opt-in; live charging is production-only. */
export function billingMode(env: NodeJS.ProcessEnv = process.env): BillingMode {
  const configured = env.VATA_BILLING_MODE;
  if (env.NODE_ENV === 'production') return configured === 'live' ? 'live' : 'disabled';
  return configured === 'test' ? 'test' : 'disabled';
}

export function billingLivemode() {
  return billingMode() === 'live';
}

export function assertStripeMode(actual: unknown, expected: 'test' | 'live') {
  if (actual !== (expected === 'live')) throw new Error('Stripe connection does not match the configured billing mode.');
}

export function stripeRedirect(url: unknown, host: 'checkout.stripe.com' | 'billing.stripe.com') {
  if (typeof url !== 'string') throw new Error('Stripe did not return a secure billing URL.');
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || parsed.hostname !== host || parsed.username || parsed.password || parsed.port) {
    throw new Error('Stripe did not return a secure billing URL.');
  }
  return url;
}
