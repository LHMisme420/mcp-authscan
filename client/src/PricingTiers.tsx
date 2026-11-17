import { useRef, useState, type FormEvent, type ReactNode } from 'react';
import { writtenScopeMailto } from './writtenScopeMailto';

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

export default function PricingTiers(props: {
  emailHref: string;
  homepageVariant?: boolean;
  renderLead?: (openForm: () => void) => ReactNode;
}) {
  const { homepageVariant = false, renderLead } = props;
  const [formOpen, setFormOpen] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  const emailLinkRef = useRef<HTMLAnchorElement>(null);
  const [draftMessage, setDraftMessage] = useState('');
  const openForm = () => setFormOpen(true);

  function submitScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    if (!emailLinkRef.current) return;
    emailLinkRef.current.href = writtenScopeMailto(new FormData(form));
    setDraftMessage('Your email app should open with a plain-text draft. It has not been sent; review it and press Send.');
    emailLinkRef.current.click();
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
          <form className="written-scope-form" ref={formRef} onSubmit={submitScope}>
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
            {draftMessage && <p className="written-scope-result" role="status">{draftMessage}</p>}
            <button className="button" type="submit">Submit</button>
            <p className="written-scope-email-fallback">
              Fallback: opens your email app with these answers as a plain-text draft. Review it, then press Send.
              {' '}<a
                ref={emailLinkRef}
                href="mailto:lhmisme2011@gmail.com"
                onClick={(event) => {
                  if (formRef.current) event.currentTarget.href = writtenScopeMailto(new FormData(formRef.current));
                }}
              >Email us</a>
            </p>
          </form>
        </div>
      )}
    </section>
    </>
  );
}
