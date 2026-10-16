export function billingGuidance(status: string, cancelAtPeriodEnd = false) {
  switch (status) {
    case 'past_due':
      return {
        title: 'Subscription payment overdue',
        detail: 'An existing subscription payment failed or is overdue. This is not a cancellation or a new Free workspace. Pro features are paused until Stripe confirms an active subscription.',
        recovery: true,
      };
    case 'unpaid':
      return {
        title: 'Subscription unpaid',
        detail: 'Stripe has stopped automatic payment attempts after an unpaid subscription payment. Your subscription has not been canceled, but Pro features are paused.',
        recovery: true,
      };
    case 'incomplete':
      return {
        title: 'Initial payment incomplete',
        detail: 'Your subscription was created, but its first payment has not completed or needs payment authentication. Pro has not started. This is not a failed renewal.',
        recovery: true,
      };
    case 'canceled':
      return { title: 'Subscription canceled', detail: 'Your previous subscription has ended. You can continue on Free or start a new Pro subscription.', recovery: false };
    case 'incomplete_expired':
      return { title: 'Initial payment expired', detail: 'The first payment was not completed in time, so that subscription ended without activating Pro. You can start a new checkout.', recovery: false };
    case 'active':
      return cancelAtPeriodEnd
        ? { title: 'Cancellation scheduled', detail: 'Your subscription is active until the end of its paid period, then it will end. This is not a failed payment. Manage the scheduled cancellation in Stripe.', recovery: false }
        : { title: 'Subscription active', detail: 'Stripe reports an active subscription.', recovery: false };
    case 'none':
      return { title: 'No subscription yet', detail: 'This workspace is on Free and has no subscription to recover.', recovery: false };
    default:
      return { title: 'Existing subscription needs review', detail: 'Review your existing subscription in Stripe before starting any new payment. Pro access requires a confirmed active subscription.', recovery: false };
  }
}
