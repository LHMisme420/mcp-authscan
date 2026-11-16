import { useState, type FormEvent } from 'react';
import PublicSiteLayout from './PublicSiteLayout';
import { assessmentEmail } from './AssessmentSections';
import { assessmentDraftUrl, assessmentHostnamePattern, isValidAssessmentHostname, type AssessmentPackageChoice } from './assessmentForm';
import './commercial.css';

const packageNames: Record<AssessmentPackageChoice, string> = {
  private: 'Private assessment — $3,500',
  publication: 'Assessment with publication — $2,500',
};

export default function Assessment() {
  const [selectedOption, setSelectedOption] = useState<AssessmentPackageChoice | null>(null);

  return (
    <PublicSiteLayout className="assessment-buy-page">
      <section className="wrap public-page-heading assessment-buy-heading">
        <span className="eyebrow">Independent, scoped MCP security review</span>
        <h1>An MCP AuthScan assessment</h1>
        <h2>Evidence an enterprise buyer will accept</h2>
        <p>An independent assessment of your MCP surface, written for the person holding your contract, not for your engineering team.</p>
      </section>

      <section className="wrap assessment-buy-opening">
        <p>Your buyer&apos;s security review asks a question your own engineer cannot answer with authority: what can a stranger actually reach on this deployment. Output from a tool you ran yourself is a claim. This is the record a stranger can re-run.</p>
      </section>

      <section className="wrap assessment-buy-content" aria-labelledby="assessment-includes-title">
        <div className="assessment-copy-block">
          <span className="eyebrow">The written record</span>
          <h2 id="assessment-includes-title">What the assessment includes:</h2>
          <p>Who authorized the test, on what basis, and the exact scope, written on the first page. The endpoint tested and the tool and probe-set versions used. Every probe that returned a verdict, and every probe that did not with the reason it could not. Findings graded by severity, with the basis for each severity stated rather than asserted. A content hash over the graded fields, so a second party can re-run the same probe set against the same endpoint and compare. A written fix list with the change that closes each finding. A retest after you fix, on the same terms.</p>
        </div>
        <aside className="assessment-exclusions">
          <span className="eyebrow">The boundaries</span>
          <h2>What is not included, stated plainly:</h2>
          <p>no exploitation, no load testing, no writes or deletes, no tool calls outside a written per-action permission, no other tenants, no source code review, no dependency audit. If it is not on this list, it did not happen and the report will say so.</p>
        </aside>
      </section>

      <section className="wrap assessment-options" aria-label="Assessment options">
        <article className={`assessment-option ${selectedOption === 'private' ? 'is-selected' : ''}`}>
          <span className="eyebrow">Option one</span>
          <strong className="assessment-option-price">$3,500</strong>
          <h2>Option one, the assessment: three thousand five hundred dollars.</h2>
          <p>One MCP endpoint, or a small set on the same host. Unauthenticated requests only. No client registration, no token issuance, no write, delete or execute. One retest after your fixes. The report is private to you, and nothing is said publicly about it, ever, unless you ask me to.</p>
          <button className="button" type="button" aria-expanded={selectedOption === 'private'} aria-controls="assessment-inquiry-form" onClick={() => setSelectedOption('private')}>Start an assessment</button>
          {selectedOption === 'private' && <p className="option-selection" role="status">Selected: private assessment, $3,500.</p>}
        </article>
        <article className={`assessment-option publication-option ${selectedOption === 'publication' ? 'is-selected' : ''}`}>
          <span className="eyebrow">Option two</span>
          <strong className="assessment-option-price">$2,500</strong>
          <h2>Option two, the assessment with publication: two thousand five hundred dollars.</h2>
          <p>Same scope, same report. You save money because you are giving me the one thing I want: permission to publish a redacted version with your name on it, after your fix window closes. You see the redaction before it goes out. You get a public record that a third party tested your surface and you fixed what it found, which is worth more to your next buyer than the report itself.</p>
          <button className="button" type="button" aria-expanded={selectedOption === 'publication'} aria-controls="assessment-inquiry-form" onClick={() => setSelectedOption('publication')}>Start an assessment</button>
          {selectedOption === 'publication' && <p className="option-selection" role="status">Selected: assessment with publication, $2,500.</p>}
        </article>
      </section>

      <section className="wrap assessment-terms">
        <span className="eyebrow">Before anything runs</span>
        <h2>Both options, the same terms:</h2>
        <p>scope confirmed in writing before anything runs. Nothing runs outside that scope. Findings come to you first. Fix window before any public mention, on the published option. If a finding turns out to be intentional design on your side, it comes out of the report and the record says why.</p>
      </section>

      {selectedOption && <AssessmentInquiry selectedOption={selectedOption} />}
    </PublicSiteLayout>
  );
}

export function AssessmentInquiry({ selectedOption }: { selectedOption: AssessmentPackageChoice }) {
  const [company, setCompany] = useState('');
  const [hostname, setHostname] = useState('');
  const [email, setEmail] = useState('');
  const [copyMessage, setCopyMessage] = useState('');

  async function copyRecipient() {
    try {
      await navigator.clipboard.writeText(assessmentEmail);
      setCopyMessage('Recipient copied.');
    } catch {
      setCopyMessage('Copy is unavailable here. Select and copy the recipient address above.');
    }
  }

  function submitInquiry(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!isValidAssessmentHostname(hostname)) return;
    window.location.href = assessmentDraftUrl(selectedOption, company.trim(), hostname.trim(), email.trim());
  }

  return (
    <section className="wrap assessment-inquiry" id="assessment-inquiry-form" aria-labelledby="assessment-form-title">
          <div className="assessment-form-intro">
            <span className="eyebrow">Written scope starts here</span>
            <h2 id="assessment-form-title">Start an assessment</h2>
            <p>Scoped and confirmed by email before a single request is sent. If your surface is outside the scope above, tell me the shape of it and I will quote the wider one.</p>
          </div>
          <form className="assessment-start-form" onSubmit={submitInquiry}>
            <p className="assessment-selected-package">Selected option: <strong>{packageNames[selectedOption]}</strong></p>
            <label htmlFor="assessment-company">Company <span aria-hidden="true">*</span></label>
            <input id="assessment-company" name="company" autoComplete="organization" required value={company} onChange={event => setCompany(event.target.value)} />
            <label htmlFor="assessment-hostname">Endpoint host <span aria-hidden="true">*</span></label>
            <input id="assessment-hostname" name="hostname" type="text" required pattern={assessmentHostnamePattern} title="Enter a hostname only, such as api.example.com. Do not include a scheme, path, port, or credentials." spellCheck={false} placeholder="api.example.com" value={hostname} onChange={event => setHostname(event.target.value)} />
            <span className="field-help">Hostname only. Do not include a URL scheme, path, port, credentials, or secrets.</span>
            <label htmlFor="assessment-email">Contact email <span aria-hidden="true">*</span></label>
            <input id="assessment-email" name="email" type="email" autoComplete="email" required value={email} onChange={event => setEmail(event.target.value)} />
            <button className="button" type="submit">Open email draft</button>
            <p className="email-send-note">This opens a prefilled draft in your email app. This website does not send or submit it. Review the details and send it yourself.</p>
          </form>
          <div className="assessment-recipient">
            <span className="eyebrow">Recipient and manual option</span>
            <p>Send your inquiry to <strong className="contact-mail">{assessmentEmail}</strong>.</p>
            <button className="copy-recipient" type="button" onClick={() => void copyRecipient()}>Copy recipient address</button>
            <span className="field-help" aria-live="polite">{copyMessage}</span>
            <p>If no email app opens, copy the recipient above into Gmail or another webmail service. Include your selected option, company, endpoint host, and contact email. Review your message and send it manually.</p>
          </div>
    </section>
  );
}
