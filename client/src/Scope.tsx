import PublicSiteLayout from './PublicSiteLayout';
import { useEffect, useState, type FormEvent } from 'react';
import { scopeRequestEmail, type ScopeRequest } from '../../shared/scopeRequest';
import './commercial.css';

export default function Scope() {
  const [challenge, setChallenge] = useState<string | null>(null);
  const [readyAt, setReadyAt] = useState(0);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const [sent, setSent] = useState(false);
  const [fallback, setFallback] = useState('mailto:lhmisme2011@gmail.com');

  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    fetch('/contact/scope-request/status', { signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error();
        const status = await response.json();
        if (!status.available || typeof status.challenge !== 'string') throw new Error();
        setChallenge(status.challenge);
        setReadyAt(Date.now() + 2000);
      })
      .catch(() => setError('Online delivery is unavailable. Use the email fallback below.'))
      .finally(() => clearTimeout(timeout));
    return () => { clearTimeout(timeout); controller.abort(); };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    const fields = new FormData(event.currentTarget);
    const value = Object.fromEntries(['endpoint', 'name', 'email', 'authority', 'buyerNeeds']
      .map(key => [key, String(fields.get(key) || '').trim()])) as ScopeRequest;
    setFallback(`mailto:lhmisme2011@gmail.com?subject=${encodeURIComponent('MCP AuthScan assessment scope request')}&body=${encodeURIComponent(scopeRequestEmail(value, new Date().toISOString()))}`);
    if (!challenge) { setError('Online delivery is unavailable. Use the email fallback below.'); return; }
    setPending(true);
    setError('');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      await new Promise(resolve => setTimeout(resolve, Math.max(0, readyAt - Date.now())));
      const response = await fetch('/contact/scope-request', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...value, challenge, websiteExtra: '' }), signal: controller.signal,
      });
      const result = await response.json();
      if (!response.ok || result.accepted !== true) throw new Error();
      setSent(true);
    } catch {
      setError('Delivery could not be confirmed. Your entries are still here; retry or use the email fallback below.');
    } finally { clearTimeout(timeout); setPending(false); }
  }

  if (sent) return <PublicSiteLayout className="landing"><section className="wrap landing-section"><p role="status">scope received, you will get a written scope and authorization to confirm before anything is tested.</p></section></PublicSiteLayout>;

  return (
    <PublicSiteLayout className="landing">
      <section className="wrap landing-section" aria-labelledby="scope-title">
        <div className="section-head">
          <div>
            <span className="eyebrow">Written authorization first</span>
            <h1 id="scope-title">Start a scope request</h1>
          </div>
          <p>Send the server URL and who authorizes the test. Scope and written authorization are agreed by email before anything is tested. Do not include credentials, tokens or secrets in email.</p>
        </div>
        <div className="written-scope-form-wrap">
          <form className="written-scope-form" onSubmit={submit}>
            <label htmlFor="request-endpoint">MCP server URL</label>
            <input id="request-endpoint" name="endpoint" type="url" maxLength={2000} required />
            <label htmlFor="request-name">Name</label>
            <input id="request-name" name="name" autoComplete="name" maxLength={100} required />
            <label htmlFor="request-email">Email</label>
            <input id="request-email" name="email" type="email" autoComplete="email" maxLength={254} required />
            <label htmlFor="request-authority">Who authorizes the test</label>
            <input id="request-authority" name="authority" maxLength={2000} required />
            <label htmlFor="request-buyer-needs">What the buyer needs the report to prove (optional)</label>
            <input id="request-buyer-needs" name="buyerNeeds" maxLength={2000} />
            {error && <p role="alert">{error}</p>}
            <button className="button" type="submit" disabled={pending}>{pending ? 'Submitting…' : 'Submit'}</button>
            <p><a href={fallback}>Email fallback: lhmisme2011@gmail.com</a></p>
          </form>
        </div>
      </section>
    </PublicSiteLayout>
  );
}
