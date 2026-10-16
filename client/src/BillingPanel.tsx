import { useCallback, useEffect, useState } from 'react';
import { api } from './api';
import { billingGuidance } from './billingGuidance';

type BillingStatus = {
  plan: 'free' | 'pro';
  status: string;
  available: boolean;
  testMode: boolean;
  mode: 'test' | 'live' | 'disabled';
  checkoutReady: boolean;
  hasSubscription: boolean;
  cancelAtPeriodEnd: boolean;
  price: { amount: number; currency: 'usd'; interval: 'month' } | null;
};

type Props = {
  isOwner: boolean;
  onRefresh?: () => void | Promise<void>;
};

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'Something went wrong. Please try again.';
}

export default function BillingPanel({ isOwner, onRefresh }: Props) {
  const [billing, setBilling] = useState<BillingStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await api.getBillingStatus() as BillingStatus;
      if ((result?.plan !== 'free' && result?.plan !== 'pro') || typeof result.available !== 'boolean') {
        throw new Error('Billing status was not returned in the expected format.');
      }
      setBilling(result);
    } catch (e) {
      setError(`Billing details are temporarily unavailable: ${errorMessage(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const params = new URLSearchParams(window.location.search);
    if (params.get('billing') === 'success') {
      setNotice('Checkout returned successfully. Your plan is not active until Stripe confirms it; refresh billing to verify.');
    } else if (params.get('billing') === 'cancelled') {
      setNotice('Checkout was closed. Refresh billing to verify your current subscription status.');
    }
  }, [load]);

  async function redirectTo(endpoint: 'checkout' | 'portal') {
    if (busy || !isOwner) return;
    setBusy(true);
    setError('');
    try {
      const response = endpoint === 'checkout'
        ? await api.createCheckout() as { url?: string }
        : await api.createBillingPortal() as { url?: string };
      if (!response?.url) throw new Error('A secure billing link was not returned.');
      const url = new URL(response.url);
      const host = endpoint === 'checkout' ? 'checkout.stripe.com' : 'billing.stripe.com';
      if (url.protocol !== 'https:' || url.hostname !== host || url.username || url.password || url.port) {
        throw new Error('The billing link is not a trusted Stripe URL.');
      }
      window.location.assign(url.href);
    } catch (e) {
      setError(`Unable to open ${endpoint === 'checkout' ? 'checkout' : 'the billing portal'}: ${errorMessage(e)}`);
      setBusy(false);
    }
  }

  async function refresh() {
    if (busy || !isOwner) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await api.refreshBilling();
      const result = await api.getBillingStatus() as BillingStatus;
      if ((result?.plan !== 'free' && result?.plan !== 'pro') || typeof result.available !== 'boolean') {
        throw new Error('Billing status was not returned in the expected format.');
      }
      setBilling(result);
      setNotice(!result.available
        ? 'Billing could not be verified. Your scans and history remain available.'
        : result.plan === 'pro'
          ? 'Stripe confirms Pro is active for this workspace.'
          : `${billingGuidance(result.status, result.cancelAtPeriodEnd).detail} Unlimited manual scans and full scan history remain free.`);
      await onRefresh?.();
    } catch (e) {
      setError(`Unable to refresh billing: ${errorMessage(e)}`);
    } finally {
      setBusy(false);
    }
  }

  const planName = billing?.plan === 'pro' && billing.available ? 'Pro' : 'Free';
  const guidance = billing?.available ? billingGuidance(billing.status, billing.cancelAtPeriodEnd) : null;
  // Unknown states fail closed; only a confirmed new/ended subscription permits checkout.
  const canStartCheckout = billing?.available && billing.hasSubscription === false &&
    ['none', 'canceled', 'incomplete_expired'].includes(billing.status);

  return <section className="feature-panel billing-panel" id="billing-panel" aria-label="Billing and plan">
    <header className="panel-head">
      <div><h2 className="panel-title">Plan &amp; billing</h2><p className="panel-subtitle">Manage workspace access and subscription status.</p></div>
      {error && <button className="button quiet small" type="button" onClick={() => void load()} disabled={loading}>Retry</button>}
    </header>
    <div className="feature-body">
       {billing?.mode === 'test' && <div className="billing-test-note"><strong>Test mode</strong><span>Checkout and subscription changes are in test mode. No real payment will be collected.</span></div>}
       {billing?.mode === 'live' && <div className="billing-test-note"><strong>Live billing</strong><span>Pro is $99 USD per month, billed automatically until cancelled. Manage or cancel through the Stripe billing portal.</span></div>}
      {notice && <div className="feature-alert success" role="status">{notice}</div>}
      {error && <div className="feature-alert" role="alert">{error}</div>}
      {loading && !billing ? <div aria-label="Loading billing status"><div className="skeleton" /><div className="skeleton" /></div> : billing && <>
        <div className="feature-row">
          <div className="feature-row-main">
            <strong>{!billing.available ? 'Billing status unavailable' : guidance?.recovery ? 'Pro payment needs attention' : `${planName} plan`}</strong>
            <span>{planName === 'Pro' ? 'API access, automated scheduling, and up to five seats.' : 'Unlimited manual scans and full scan history.'}</span>
          </div>
          <strong className="price-note">{!billing.available ? '—' : guidance?.recovery ? 'Existing subscription' : planName === 'Pro' ? '$99 USD / month' : '$0 · Free'}</strong>
        </div>
        {guidance && <div className="billing-test-note" role="status">
          <strong>{guidance.title}</strong>
          <span>{guidance.detail}</span>
          {guidance.recovery && <span>{isOwner
            ? 'Open the secure Stripe billing portal to update your payment method and review or pay outstanding invoices. Complete any payment authentication Stripe requests. Do not start another checkout. Return here and refresh billing to verify recovery; updating a card alone does not confirm Pro access.'
            : 'Ask your workspace owner to update the payment method and review outstanding invoices in the Stripe billing portal. Do not start another checkout.'}</span>}
          <span>Unlimited manual scans and full scan history remain free.</span>
        </div>}
        <div className="billing-actions">
          {isOwner ? <>
             {canStartCheckout && <button className="button small" type="button" disabled={busy || !billing.checkoutReady} onClick={() => void redirectTo('checkout')}>{busy ? 'Opening…' : 'Upgrade · $99 USD/month'}</button>}
            <button className="button secondary small" type="button" disabled={busy || !billing.available || billing.status === 'none'} onClick={() => void redirectTo('portal')}>{busy ? 'Opening…' : guidance?.recovery ? 'Fix payment in Stripe' : 'Manage subscription'}</button>
            <button className="button quiet small" type="button" disabled={busy} onClick={() => void refresh()}>{busy ? 'Checking…' : 'Refresh billing'}</button>
          </> : <p className="feature-inline-note">Only the workspace owner can manage billing. Ask your owner to change this plan.</p>}
        </div>
        {!billing.available && <p className="feature-inline-note">Billing actions are currently unavailable. Your scans and history remain available.</p>}
         {canStartCheckout && !billing.checkoutReady && <p className="feature-inline-note">New checkout is paused until signed Stripe webhook delivery is verified. Existing subscriptions can still be managed.</p>}
      </>}
    </div>
  </section>;
}
