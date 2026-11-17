import { useEffect, useState, type FormEvent, type ReactNode } from 'react';

const tiers = [
  {
    name: 'Single-server assessment',
    price: '1750 dollars',
    body: 'One MCP server or a small set of endpoints. Written scope and authorization before testing, evidence-backed findings, a written report signed by the named researcher, and one retest of the same endpoint after fixes.',
    className: '',
  },
  {
    name: 'Full assessment',
    price: '3500 dollars',
    body: 'A server or fleet, one written report, one retest, and the written scope agreed by email before testing.',
    className: 'pricing-tier-expanded',
  },
];

export default function PricingTiers({
  emailHref,
  homepageVariant = false,
  renderLead,
}: {
  emailHref: string;
  homepageVariant?: boolean;
  renderLead?: (openForm: () => void) => ReactNode;
}) {
  const [formOpen, setFormOpen] = useState(false);
  const [challenge, setChallenge] = useState<string | null>(null);
  const [availabilityChecked, setAvailabilityChecked] = useState(false);
  const [available, setAvailable] = useState(false);
  const [challengeReady, setChallengeReady] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);
  const openForm = () => setFormOpen(true);

  useEffect(() => {
    if (!formOpen) return;
    let cancelled = false;
    setChallenge(null);
    setAvailabilityChecked(false);
    setAvailable(false);
    setChallengeReady(false);
    setResult(null);
    let challengeTimer: number | undefined;
    fetch('/contact/scope/status', { credentials: 'include', signal: AbortSignal.timeout(10_000) })
      .then(async (response) => {
        if (!response.ok) throw new Error(`Status request failed (${response.status}).`);
        return response.json();
      })
      .then((data: { available?: boolean; challenge?: string | null }) => {
        if (cancelled) return;
        setAvailabilityChecked(true);
        setAvailable(data.available === true && typeof data.challenge === 'string' && data.challenge.length > 0);
        setChallenge(typeof data.challenge === 'string' ? data.challenge : null);
        challengeTimer = window.setTimeout(() => {
          if (!cancelled) setChallengeReady(true);
        }, 2000);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setAvailabilityChecked(true);
        setAvailable(false);
        setResult({
          kind: 'error',
          text: error instanceof Error ? `Assessment request service status could not be checked: ${error.message}` : 'Assessment request service status could not be checked.',
        });
      });
    return () => {
      cancelled = true;
      window.clearTimeout(challengeTimer);
    };
  }, [formOpen]);

  async function submitScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!available || !challenge || !challengeReady || submitting) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const payload = {
      name: String(data.get('name') || ''),
      email: String(data.get('email') || ''),
      company: String(data.get('company') || ''),
      endpoints: String(data.get('endpoints') || ''),
      service: 'comprehensive' as const,
      authority: String(data.get('authority') || ''),
      environment: '',
      buyerContext: String(data.get('buyerContext') || ''),
      publicationPermission: data.get('publicationPermission') === 'on',
      authorized: data.get('authorized') === 'on',
      challenge,
      websiteExtra: '',
    };
    setSubmitting(true);
    setResult(null);
    try {
      const response = await fetch('/contact/scope', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(20_000),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        const fieldErrors = body && typeof body.errors === 'object'
          ? Object.entries(body.errors).map(([field, message]) => `${field}: ${String(message)}`).join(' ')
          : '';
        throw new Error([body?.error || `Request failed (${response.status}).`, fieldErrors].filter(Boolean).join(' '));
      }
      if (body?.saved !== true || body?.emailed !== true) {
        throw new Error(body?.message || 'The service did not confirm that the request was saved and emailed.');
      }
      setResult({
        kind: 'success',
        text: 'Scope received. You will get a written reply.',
      });
      form.reset();
    } catch (error) {
      setResult({
        kind: 'error',
        text: error instanceof Error ? error.message : 'The request could not be submitted.',
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
    {renderLead?.(openForm)}
    <section className="pricing-tiers" aria-labelledby="pricing-tiers-title">
      <h2 id="pricing-tiers-title">Independent MCP security assessments</h2>
      <div className="pricing-tier-grid">
        {tiers.map((tier, index) => (
          <article className={`pricing-tier ${tier.className}`} key={tier.name}>
            <span className="pricing-tier-index">0{index + 1}</span>
            <h3>{tier.name}</h3>
            <strong className="pricing-tier-price">{tier.price}</strong>
            <p>{tier.body}</p>
            {(tier.name === 'Full assessment' || (homepageVariant && tier.name === 'Single-server assessment')) && (
              <button className="button pricing-start-button" type="button" onClick={() => setFormOpen((open) => !open)}>
                {formOpen ? 'Close assessment form' : 'Start an assessment'}
              </button>
            )}
          </article>
        ))}
      </div>
      {formOpen && (
        <div className="written-scope-form-wrap">
          {result?.kind === 'success' ? <p role="status">{result.text}</p> :
          <form className="written-scope-form" onSubmit={submitScope}>
            <div className="written-scope-form-heading">
              <span className="pricing-tier-index">WRITTEN SCOPE REQUEST</span>
              <h3>Assessment details</h3>
            </div>
            <label htmlFor="scope-name">Your name</label>
            <input id="scope-name" name="name" autoComplete="name" required />
            <label htmlFor="scope-email">Work email</label>
            <input id="scope-email" name="email" type="email" autoComplete="email" required />
            <label htmlFor="scope-company">Company</label>
            <input id="scope-company" name="company" autoComplete="organization" required />
            <label htmlFor="scope-endpoints">MCP endpoint or URL</label>
            <textarea id="scope-endpoints" name="endpoints" rows={4} required />
            <label htmlFor="scope-authority">Who authorizes the test and on what basis</label>
            <textarea id="scope-authority" name="authority" rows={3} required />
            <label htmlFor="scope-buyer-context">What buyer or review is waiting on it</label>
            <textarea id="scope-buyer-context" name="buyerContext" rows={3} required />
            <label className="written-scope-check">
              <input type="checkbox" name="publicationPermission" />
              <span>Permission to publish a redacted result</span>
            </label>
            <label className="written-scope-check">
              <input type="checkbox" name="authorized" required />
              <span>I confirm I own this endpoint, or am authorized to approve testing of it, and I will confirm the scope in writing before any test runs.</span>
            </label>
            {availabilityChecked && !available && (
              <p className="written-scope-unavailable" role="status">
                Online saving and email are currently unavailable. Use the existing email fallback to send your written scope request.
                {' '}<a href={emailHref}>Email us</a>
              </p>
            )}
            {result && (
              <p className={`written-scope-result ${result.kind}`} role={result.kind === 'error' ? 'alert' : 'status'}>
                {result.text}
              </p>
            )}
            <button className="button" type="submit" disabled={!available || !challenge || !challengeReady || submitting}>
              {submitting ? 'Submitting…' : 'Submit'}
            </button>
            {!challengeReady && <span className="field-help" aria-live="polite">Preparing secure request…</span>}
          </form>}
        </div>
      )}
    </section>
    </>
  );
}
