import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';

const message = (error: unknown) => error instanceof Error ? error.message : 'Test checkout is unavailable.';

export default function TestCheckoutPanel() {
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const requestId = useRef(crypto.randomUUID());
  const session = new URLSearchParams(window.location.search).get('test_checkout_session');
  const load = useCallback(async () => {
    setReady(false); setError('');
    try {
      const data = await api.getTestCheckout();
      if (!data.enabled || data.mode !== 'test') throw new Error('Test checkout is not enabled.');
      setReady(true);
    } catch (e) { setError(message(e)); }
  }, []);
  const verify = useCallback(async (id: string) => {
    setBusy(true); setError('');
    try {
      const data = await api.verifyTestCheckout(id);
      if (data.mode !== 'test' || data.accessChanged !== false) throw new Error('Unexpected verification response.');
      setNotice(data.confirmed
        ? `Test payment confirmed by Stripe. Subscription: ${data.subscriptionStatus ?? 'pending'}. No real charge was made and workspace access is unchanged.`
        : `Test checkout is ${data.status ?? 'pending'}. No completed payment has been confirmed.`);
    } catch (e) { setError(message(e)); }
    finally { setBusy(false); }
  }, []);
  useEffect(() => {
    void load();
    const params = new URLSearchParams(window.location.search);
    if (params.get('test_checkout_cancelled') === '1') setNotice('Test checkout was canceled. Access is unchanged.');
    const id = params.get('test_checkout_session');
    if (id) void verify(id);
  }, [load, verify]);
  async function checkout() {
    setBusy(true); setError('');
    try {
      const data = await api.createTestCheckout(requestId.current);
      const url = new URL(data.checkout_url);
      if (data.mode !== 'test' || url.protocol !== 'https:' || url.hostname !== 'checkout.stripe.com') {
        throw new Error('Invalid hosted test checkout response.');
      }
      window.location.assign(url.href);
    } catch (e) { setError(message(e)); setBusy(false); }
  }
  return <section className="panel" aria-label="Stripe test checkout">
    <header className="panel-head"><div>
      <h2 className="panel-title">Stripe sandbox · test only</h2>
      <p className="panel-subtitle">$99 USD/month test subscription. Preview only. No real charges or paid restrictions.</p>
    </div></header>
    <div className="panel-body">
      <p>Use test card 4242 4242 4242 4242, any future expiry, and any three-digit CVC. Do not use a real card.</p>
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert">{error}</p>}
      <button className="button" type="button" disabled={!ready || busy} onClick={() => void checkout()}>
        {busy ? 'Checking…' : 'Open test checkout'}
      </button>{' '}
      {error && <button className="button secondary" type="button" onClick={() => void load()}>Retry connection</button>}
      {session && <button className="button secondary" type="button" disabled={busy} onClick={() => void verify(session)}>Recheck test payment</button>}
    </div>
  </section>;
}
