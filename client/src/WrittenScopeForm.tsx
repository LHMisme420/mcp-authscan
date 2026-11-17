import { useRef, useState, type FormEvent } from 'react';
import { writtenScopeMailto } from './writtenScopeMailto';

export default function WrittenScopeForm() {
  const formRef = useRef<HTMLFormElement>(null);
  const emailLinkRef = useRef<HTMLAnchorElement>(null);
  const [draftMessage, setDraftMessage] = useState('');
  const [publicationPermission, setPublicationPermission] = useState(false);
  const [authorized, setAuthorized] = useState(false);

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
        <input
          type="checkbox"
          name="publicationPermission"
          onChange={(event) => setPublicationPermission(event.currentTarget.checked)}
        />
        <span>Permission to publish a redacted result</span>{' '}
        <span aria-live="polite">{publicationPermission ? 'Yes' : 'No'}</span>
      </label>
      <label className="written-scope-check">
        <input
          type="checkbox"
          name="authorized"
          required
          onChange={(event) => setAuthorized(event.currentTarget.checked)}
        />
        <span>I confirm I own this endpoint, or am authorized to approve testing of it, and I will confirm the scope in writing before any test runs.</span>{' '}
        <span aria-live="polite">{authorized ? 'Yes' : 'No'}</span>
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
  );
}
