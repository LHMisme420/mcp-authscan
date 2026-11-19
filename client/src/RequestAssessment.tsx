import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Link } from 'wouter';
import PublicSiteLayout from './PublicSiteLayout';
import { assessmentMailto } from './AssessmentSections';
import { assessmentPackages, validateInquiry, type AssessmentInquiry, type InquiryErrors } from '../../shared/assessmentInquiry';

type InquiryForm = Omit<AssessmentInquiry, 'servers'> & { servers: string };
type StatusResponse = { available: boolean; challenge: string | null; testMode?: boolean };

const emptyForm: InquiryForm = {
  name: '', email: '', company: '', website: '', service: 'undecided', servers: '1', timeframe: '', scope: '',
};

function getInitialForm(): InquiryForm {
  if (typeof window === 'undefined') return emptyForm;
  const requestedPackage = new URLSearchParams(window.location.search).get('package');
  if (requestedPackage === 'verification' || requestedPackage === 'comprehensive') {
    return { ...emptyForm, service: requestedPackage };
  }
  return emptyForm;
}

export default function RequestAssessment() {
  const [form, setForm] = useState<InquiryForm>(getInitialForm);
  const [errors, setErrors] = useState<InquiryErrors>({});
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<{ tone: 'error' | 'success'; text: string } | null>(null);
  const [readyToSubmit, setReadyToSubmit] = useState(false);
  const submitInFlight = useRef(false);
  const honeypot = useRef<HTMLInputElement>(null);

  const refreshStatus = async () => {
    setStatusLoading(true);
    setStatusError('');
    try {
      const response = await fetch('/contact/assessment/status', { headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('Inquiry delivery is not available right now.');
      const data = await response.json() as StatusResponse;
      if (typeof data.available !== 'boolean' || (data.available && typeof data.challenge !== 'string')) {
        throw new Error('Inquiry delivery setup could not be confirmed.');
      }
      setStatus(data);
    } catch {
      setStatus(null);
      setStatusError('The inquiry service is not available or configured at this time.');
    } finally {
      setStatusLoading(false);
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  useEffect(() => {
    setReadyToSubmit(false);
    if (!status?.challenge) return;
    const timer = window.setTimeout(() => setReadyToSubmit(true), 2100);
    return () => window.clearTimeout(timer);
  }, [status?.challenge]);

  const update = (key: keyof InquiryForm, value: string) => {
    setForm((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: undefined }));
    setMessage(null);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitInFlight.current || !status?.available || !status.challenge || !readyToSubmit) return;
    const checked = validateInquiry({ ...form, servers: Number(form.servers) });
    setErrors(checked.errors);
    setMessage(null);
    if (!checked.value) return;

    submitInFlight.current = true;
    setSubmitting(true);
    try {
      const response = await fetch('/contact/assessment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ ...checked.value, challenge: status.challenge, websiteExtra: honeypot.current?.value ?? '' }),
      });
      const result = await response.json().catch(() => ({})) as {
        accepted?: boolean; reference?: string; message?: string; error?: string; errors?: InquiryErrors;
      };
      if (!response.ok) {
        if (result.errors) setErrors(result.errors);
        if (/challenge|expired/i.test(result.error ?? '')) {
          await refreshStatus();
          setMessage({ tone: 'error', text: 'The inquiry challenge expired. A fresh challenge has been requested; your form details are unchanged.' });
        } else {
          setMessage({ tone: 'error', text: result.error || 'The inquiry could not be accepted. Your details have been kept; you can safely try again.' });
        }
        return;
      }
      if (result.accepted !== true) {
        setMessage({ tone: 'error', text: 'The server did not confirm acceptance. Your details have been kept; please retry.' });
        return;
      }
      setForm(getInitialForm());
      setErrors({});
      setMessage({
        tone: 'success',
        text: `${result.message || 'Your inquiry was accepted.'}${result.reference ? ` Reference: ${result.reference}.` : ''} Acceptance confirms provider acceptance only; it does not guarantee inbox delivery.`,
      });
      await refreshStatus();
    } catch {
      setMessage({ tone: 'error', text: 'A network error interrupted submission. Your details and challenge are unchanged so you can safely retry.' });
    } finally {
      submitInFlight.current = false;
      setSubmitting(false);
    }
  };

  const fieldError = (field: keyof AssessmentInquiry) => errors[field];
  const unavailable = !statusLoading && (!status?.available || !status.challenge);

  return (
    <PublicSiteLayout className="request-assessment-page">
      <section className="wrap public-page-heading">
        <span className="eyebrow">Independent technical review</span>
        <h1>Request an assessment</h1>
        <p>Share a little about your environment and the review you have in mind. We will use this information to discuss fit and agree scope before any engagement proceeds.</p>
      </section>
      <section className="wrap request-layout">
        <form className="inquiry-form" onSubmit={handleSubmit} noValidate aria-busy={statusLoading || submitting}>
          <fieldset disabled={submitting} className="inquiry-fields">
          <legend className="sr-only">Assessment inquiry details</legend>
          <div className="inquiry-honeypot" aria-hidden="true">
            <label htmlFor="inquiry-extra">Leave this field empty</label>
            <input id="inquiry-extra" name="websiteExtra" ref={honeypot} tabIndex={-1} autoComplete="off" />
          </div>
          <div className="inquiry-field">
            <label htmlFor="inquiry-name">Contact name</label>
            <input id="inquiry-name" name="name" autoComplete="name" required maxLength={100} value={form.name} onChange={(e) => update('name', e.target.value)} aria-invalid={!!fieldError('name')} aria-describedby={fieldError('name') ? 'error-name' : undefined} />
            {fieldError('name') && <span className="field-error" id="error-name">{fieldError('name')}</span>}
          </div>
          <div className="inquiry-field">
            <label htmlFor="inquiry-email">Business email</label>
            <input id="inquiry-email" name="email" type="email" autoComplete="email" required maxLength={254} value={form.email} onChange={(e) => update('email', e.target.value)} aria-invalid={!!fieldError('email')} aria-describedby={fieldError('email') ? 'error-email' : undefined} />
            {fieldError('email') && <span className="field-error" id="error-email">{fieldError('email')}</span>}
          </div>
          <div className="inquiry-field">
            <label htmlFor="inquiry-company">Company name</label>
            <input id="inquiry-company" name="company" autoComplete="organization" required maxLength={160} value={form.company} onChange={(e) => update('company', e.target.value)} aria-invalid={!!fieldError('company')} aria-describedby={fieldError('company') ? 'error-company' : undefined} />
            {fieldError('company') && <span className="field-error" id="error-company">{fieldError('company')}</span>}
          </div>
          <div className="inquiry-field">
            <label htmlFor="inquiry-website">Company website <span>(optional)</span></label>
            <input id="inquiry-website" name="website" type="url" autoComplete="url" maxLength={500} placeholder="https://example.com" value={form.website} onChange={(e) => update('website', e.target.value)} aria-invalid={!!fieldError('website')} aria-describedby={fieldError('website') ? 'error-website' : undefined} />
            {fieldError('website') && <span className="field-error" id="error-website">{fieldError('website')}</span>}
          </div>
          <div className="inquiry-field">
            <label htmlFor="inquiry-service">Desired assessment package</label>
            <select id="inquiry-service" name="service" value={form.service} onChange={(e) => update('service', e.target.value)} aria-invalid={!!fieldError('service')} aria-describedby={fieldError('service') ? 'error-service' : undefined}>
              {Object.entries(assessmentPackages).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
            </select>
            {fieldError('service') && <span className="field-error" id="error-service">{fieldError('service')}</span>}
          </div>
          <div className="inquiry-field">
            <label htmlFor="inquiry-servers">Number of MCP servers</label>
            <input id="inquiry-servers" name="servers" type="number" min="1" max="1000" step="1" required value={form.servers} onChange={(e) => update('servers', e.target.value)} aria-invalid={!!fieldError('servers')} aria-describedby={fieldError('servers') ? 'error-servers' : undefined} />
            {fieldError('servers') && <span className="field-error" id="error-servers">{fieldError('servers')}</span>}
          </div>
          <div className="inquiry-field full">
            <label htmlFor="inquiry-timeframe">Planned deployment timeframe</label>
            <input id="inquiry-timeframe" name="timeframe" required maxLength={120} placeholder="For example: before a planned launch this quarter" value={form.timeframe} onChange={(e) => update('timeframe', e.target.value)} aria-invalid={!!fieldError('timeframe')} aria-describedby={fieldError('timeframe') ? 'error-timeframe' : undefined} />
            {fieldError('timeframe') && <span className="field-error" id="error-timeframe">{fieldError('timeframe')}</span>}
          </div>
          <div className="inquiry-field full">
            <label htmlFor="inquiry-scope">Brief description of the assessment needed</label>
            <textarea id="inquiry-scope" name="scope" required minLength={20} maxLength={3000} placeholder="Describe the review goals and any boundaries. Do not include credentials, tokens, or secrets." value={form.scope} onChange={(e) => update('scope', e.target.value)} aria-invalid={!!fieldError('scope')} aria-describedby={fieldError('scope') ? 'error-scope' : 'scope-help'} />
            <span id="scope-help" className="field-help">Keep this high-level; no credentials or secrets.</span>
            {fieldError('scope') && <span className="field-error" id="error-scope">{fieldError('scope')}</span>}
          </div>
          </fieldset>
          {status?.testMode && <div className="form-status" role="status"><strong>Development test delivery only.</strong> This sends to the owner's Resend-account inbox using Resend's test sender. It is not a production inquiry service.</div>}
          {unavailable && <div className="form-status" role="status"><strong>Online inquiry delivery is unavailable.</strong> {statusError || 'Sending requires a configured, working email sender. It may need setup or be temporarily unavailable.'} Sending is disabled; you can use the existing email fallback below.</div>}
          {message && <div className={`form-status ${message.tone}`} role={message.tone === 'error' ? 'alert' : 'status'}>{message.text}</div>}
          <div className="form-actions">
            <button className="button" type="submit" disabled={statusLoading || unavailable || submitting || !readyToSubmit}>
              {statusLoading ? 'Checking inquiry service…' : submitting ? 'Submitting…' : unavailable ? 'Delivery unavailable' : !readyToSubmit ? 'Preparing secure form…' : status?.testMode ? 'Send test inquiry' : 'Send inquiry'}
            </button>
            {unavailable && <a className="text-link" href={assessmentMailto}>Email fallback</a>}
            {statusLoading && <span className="field-error">Checking whether secure delivery is configured.</span>}
            {unavailable && <button className="status-retry" type="button" onClick={() => void refreshStatus()}>Retry availability check</button>}
            {status?.available && !submitting && <button className="status-retry" type="button" onClick={() => void refreshStatus()}>Refresh form verification</button>}
          </div>
          <p className="field-error" style={{ gridColumn: '1 / -1', margin: 0 }}>
            This inquiry is not authorization to scan or test any system. Do not submit API keys, passwords, tokens, or other credentials.
          </p>
        </form>
        <aside className="setup-note">
          <span className="eyebrow">Scope before testing</span>
          <h2>Inquiry is not authorization.</h2>
          <p>Testing begins only after scope and written authorization are approved. An inquiry does not start a scan or reserve an engagement.</p>
          <p>Submitted inquiry details are forwarded via Resend to our assessment inbox for follow-up; they are not stored in the findings database. Email copies are retained by the provider and recipient under their respective policies. Delivery is subject to email-provider acceptance, not guaranteed inbox receipt.</p>
          <p>Need to compare packages first? <Link className="text-link" href="/assessments">Review assessment details</Link>.</p>
        </aside>
      </section>
    </PublicSiteLayout>
  );
}
