import PublicSiteLayout from './PublicSiteLayout';
import { useRef, useState } from 'react';
import './commercial.css';

export default function Scope() {
  const formRef = useRef<HTMLFormElement>(null);
  const emailRef = useRef<HTMLAnchorElement>(null);
  function draft(form?: HTMLFormElement) {
    const fields = form ? new FormData(form) : new FormData();
    const body = [
      `MCP server URL: ${fields.get('endpoint') || ''}`,
      `Name: ${fields.get('name') || ''}`,
      `Email: ${fields.get('email') || ''}`,
      `Who authorizes the test: ${fields.get('authority') || ''}`,
      `What the buyer needs the report to prove (optional): ${fields.get('buyerNeeds') || ''}`,
    ].join('\n');
    return `mailto:lhmisme2011@gmail.com?subject=${encodeURIComponent('MCP assessment scope')}&body=${encodeURIComponent(body)}`;
  }
  const [emailHref, setEmailHref] = useState(() => draft());

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
          <form
            className="written-scope-form"
            ref={formRef}
            onInput={event => setEmailHref(draft(event.currentTarget))}
            onSubmit={event => {
              event.preventDefault();
              if (event.currentTarget.reportValidity()) emailRef.current?.click();
            }}
          >
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
            <a
              className="button"
              ref={emailRef}
              href={emailHref}
              onClick={event => {
                if (!formRef.current?.reportValidity()) { event.preventDefault(); return; }
                event.currentTarget.href = draft(formRef.current);
              }}
            >Email scope request</a>
            <p>Opens a prefilled draft in your email app. Review it and press Send; nothing is sent from this site.</p>
            <p>lhmisme2011@gmail.com</p>
          </form>
        </div>
      </section>
    </PublicSiteLayout>
  );
}
