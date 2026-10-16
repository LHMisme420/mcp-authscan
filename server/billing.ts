/** Legacy account-response compatibility only. Payment processing was removed. */
export function advancedBillingEnabled() {
  return false;
}

export async function billingStatus(_account: unknown) {
  return {
    plan: 'free' as const,
    status: 'disabled',
    available: false,
    mode: 'disabled' as const,
    testMode: false,
    checkoutReady: false,
    price: null,
  };
}

/** Preserve existing subscription-free access without reading payment records. */
export async function requirePro(_account: unknown) {}
