export type BillingMode = 'disabled';

/** Payment removal is permanent for this release, even with stale environment flags. */
export function billingMode(_env: NodeJS.ProcessEnv = process.env): BillingMode {
  return 'disabled';
}
