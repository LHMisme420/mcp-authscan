export const PRO_LOOKUP_KEY = 'vata_pro_usd_monthly_v1';
export const PRO_PRICE = { amount: 9900, currency: 'usd', interval: 'month' } as const;

export function subscriptionHasEnded(status: string) {
  return ['canceled', 'incomplete_expired'].includes(status);
}

/** Interpret SDK-owned records only after the account/mode-scoped query. */
export function subscriptionBillingState(subscriptions: any[], priceId: string, account: any, livemode: boolean) {
  const owned = subscriptions.filter(subscription =>
    subscription.livemode === livemode && subscription.customer === account.stripe_customer_id &&
    subscription.metadata?.vata_account_id === String(account.id) &&
    subscription.metadata?.clerk_user_id === account.clerk_user_id);
  // Do not present another owner's subscription or offer checkout against it.
  if (owned.length !== subscriptions.length) throw new Error('Subscription ownership needs verification.');
  const paid = owned.find(subscription => subscriptionGrantsAccess(subscription, priceId, account, Date.now(), livemode));
  const existing = owned.find(subscription => !subscriptionHasEnded(subscription.status));
  const current = paid ?? existing ?? owned[0];
  return {
    plan: paid ? 'pro' as const : 'free' as const,
    status: current?.status ?? 'none',
    hasSubscription: !!existing,
    cancelAtPeriodEnd: current?.cancel_at_period_end === true,
  };
}

/** A success URL, account display name, or old tier flag never grants access. */
export function subscriptionGrantsAccess(subscription: any, priceId: string, account: any, now = Date.now(), livemode = false) {
  if (subscription?.livemode !== livemode || subscription.status !== 'active' ||
      subscription.customer !== account.stripe_customer_id ||
      subscription.metadata?.vata_account_id !== String(account.id) ||
      subscription.metadata?.clerk_user_id !== account.clerk_user_id) return false;
  return subscription.items?.data?.some((item: any) =>
    (typeof item.price === 'string' ? item.price : item.price?.id) === priceId &&
    Number(item.current_period_end ?? subscription.current_period_end) * 1000 > now,
  ) ?? false;
}

export function validProPrice(price: any, livemode: boolean) {
  const product = price?.product;
  return price?.livemode === livemode && price.active === true &&
    price.lookup_key === PRO_LOOKUP_KEY && price.currency === PRO_PRICE.currency &&
    price.unit_amount === PRO_PRICE.amount && price.recurring?.interval === PRO_PRICE.interval &&
    price.recurring.interval_count === 1 && product?.deleted !== true &&
    product?.active === true && product?.livemode === livemode && product?.metadata?.vata_plan === 'pro';
}
