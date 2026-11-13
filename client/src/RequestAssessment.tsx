import { useEffect, useState } from 'react';
import { Link } from 'wouter';
import PublicSiteLayout from './PublicSiteLayout';
import { assessmentEmail, assessmentEmailFor, type AssessmentPackage } from './AssessmentSections';

const packageChoices: Record<'verification' | 'comprehensive', AssessmentPackage> = {
  verification: 'verification',
  comprehensive: 'comprehensive',
};

function requestedPackage(): AssessmentPackage {
  if (typeof window === 'undefined') return 'undecided';
  const value = new URLSearchParams(window.location.search).get('package');
  return value === 'verification' || value === 'comprehensive' ? packageChoices[value] : 'undecided';
}

export default function RequestAssessment() {
  const [packageChoice, setPackageChoice] = useState<AssessmentPackage>('undecided');

  useEffect(() => {
    setPackageChoice(requestedPackage());
  }, []);

  return (
    <PublicSiteLayout className="request-assessment-page">
      <section className="wrap public-page-heading">
        <span className="eyebrow">Independent technical review</span>
        <h1>Request an assessment</h1>
        <p>Online submission is currently unavailable. Email is supported for assessment inquiries; use the draft template to share a proposed scope and discuss fit before any engagement proceeds.</p>
      </section>
      <section className="wrap request-layout">
        <div className="email-inquiry">
          <span className="eyebrow">Email inquiry</span>
          <h2>Start with the scope.</h2>
          <p>Include the details below in your message. Keep the description high-level and do not send credentials, API keys, tokens, passwords, or other secrets.</p>
          <a className="button email-primary-cta" href={assessmentEmailFor(packageChoice)}>Email us to request an assessment</a>
          <p className="email-send-note">Clicking opens a draft in your email app; you must review and send it. This website submits nothing.</p>
          <div className="email-address-block">
            <span className="eyebrow">Email address</span>
            <a className="contact-mail" href={`mailto:${assessmentEmail}`}>{assessmentEmail}</a>
            <p>If no email app opens, select and copy this address into Gmail or another webmail service, then send your inquiry there.</p>
          </div>
          <dl className="email-template">
            <div><dt>Name / company</dt><dd>Your name and organization</dd></div>
            <div><dt>Desired package</dt><dd>{packageChoice === 'verification' ? 'MCP Server Security Verification' : packageChoice === 'comprehensive' ? 'Comprehensive MCP Security Assessment' : 'The package you would like to discuss'}</dd></div>
            <div><dt>Target / number of servers</dt><dd>Target description and approximate MCP server count</dd></div>
            <div><dt>Scope</dt><dd>Review goals and any boundaries</dd></div>
            <div><dt>Timeframe</dt><dd>Your preferred timing</dd></div>
            <div><dt>Authorizing party</dt><dd>Who can approve the proposed testing</dd></div>
          </dl>
        </div>
        <aside className="setup-note">
          <span className="eyebrow">Scope before testing</span>
          <h2>Inquiry is not authorization.</h2>
          <p>Testing begins only after scope and written authorization are approved. An inquiry does not start a scan or reserve an engagement.</p>
          <p>Your email is handled by your email provider and the recipient under their respective privacy and retention policies. This website does not submit or store your inquiry. Email delivery depends on the providers involved and is not guaranteed.</p>
          <p>Actual testing is limited to agreed scope, available credentials, supported techniques, and written authorization. No certification, complete-coverage, or security guarantee is implied.</p>
          <p><Link className="text-link" href="/sample-assessment">Review the synthetic sample report</Link></p>
          <p>Need to compare packages first? <Link className="text-link" href="/assessments">Review assessment details</Link>.</p>
        </aside>
      </section>
    </PublicSiteLayout>
  );
}
