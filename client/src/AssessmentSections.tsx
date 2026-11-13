import { Link } from 'wouter';

const assessmentMailtoBase = 'mailto:lhmisme2011@gmail.com';
export const assessmentEmail = assessmentMailtoBase.slice('mailto:'.length);

export type AssessmentPackage = 'verification' | 'comprehensive' | 'undecided';

const packageDetails: Record<AssessmentPackage, { label: string }> = {
  verification: {
    label: 'MCP Server Security Verification',
  },
  comprehensive: {
    label: 'Comprehensive MCP Security Assessment',
  },
  undecided: {
    label: 'Assessment package to discuss',
  },
};

export function assessmentEmailFor(packageChoice: string = 'undecided') {
  const details = packageDetails[packageChoice === 'verification' || packageChoice === 'comprehensive' ? packageChoice : 'undecided'];
  const subject = `MCP AuthScan inquiry — ${details.label}`;
  const body = [
    'Hello, I would like to discuss an MCP AuthScan independent assessment.',
    '',
    'Name / company:',
    `Desired package: ${details.label}`,
    'Target and number of MCP servers:',
    'Scope:',
    'Timeframe:',
    'Authorizing party:',
    '',
    'No credentials, tokens, passwords, or other secrets are included.',
  ].join('\n');
  return `${assessmentMailtoBase}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

// Kept as a compatibility export for existing callers.
export const assessmentMailto = assessmentEmailFor();

export function AssessmentServices() {
  return (
    <section className="landing-section commercial-section" id="assessments">
      <div className="wrap">
        <div className="assessment-intro">
          <div>
            <span className="eyebrow">Independent, scoped review</span>
            <h2>Evidence you can inspect. Limits you can see.</h2>
          </div>
          <p>
            MCP AuthScan provides paid independent reviews of authorized MCP servers. Leroy H. Mason,
            independent AI security researcher and credited reporter on published MCP security advisories,
            signs the written report. This is not a certification, safety guarantee, promise of complete
            coverage, or guarantee that a buyer will accept the report.
          </p>
        </div>

        <div className="commercial-grid">
          <article className="commercial-offer">
            <div className="offer-topline">
              <span>Single server</span>
              <strong className="offer-price">$1,750</strong>
            </div>
            <h3>MCP Server Security Assessment</h3>
            <p>One MCP server or a small set of endpoints, one written report, one retest.</p>
            <ul className="package-includes">
              <li>Handshake and supported protocol-security checks</li>
              <li>An authorized tool-call check within the agreed, supported scope</li>
              <li>Written report signed by Leroy H. Mason</li>
              <li>Observed evidence, severity rationale, and remediation guidance</li>
              <li>One retest after remediation, when requested and agreed</li>
            </ul>
            <div className="offer-bottom">
              <div className="offer-cta-stack">
                <a className="button" href={assessmentEmailFor('verification')}>Email us to request an assessment</a>
                <Link className="text-link" href="/request-assessment?package=verification">No email app? See email instructions</Link>
              </div>
              <span>Written authorization and scope before testing</span>
            </div>
          </article>

          <article className="commercial-offer expanded">
            <div className="offer-topline">
              <span>Full assessment</span>
              <strong className="offer-price">$3,500</strong>
            </div>
            <h3>Full MCP Security Assessment</h3>
            <p>A server or fleet, one written report, one retest, and a call to walk your team through the findings.</p>
            <ul className="package-includes">
              <li>Mutually agreed scope across the server or fleet</li>
              <li>Handshake and supported protocol-security checks</li>
              <li>An authorized tool-call check within the agreed, supported scope</li>
              <li>Written report signed by Leroy H. Mason</li>
              <li>Observed evidence, severity rationale, and remediation guidance</li>
              <li>One retest after remediation, when requested and agreed</li>
              <li>Walkthrough call to discuss the findings</li>
            </ul>
            <div className="offer-bottom">
              <div className="offer-cta-stack">
                <a className="button" href={assessmentEmailFor('comprehensive')}>Email us to request an assessment</a>
                <Link className="text-link" href="/request-assessment?package=comprehensive">No email app? See email instructions</Link>
              </div>
              <span>Retest and testing criteria remain within agreed scope</span>
            </div>
          </article>
        </div>

        <div className="scope-caveat">
          <strong>Scope and authorization come first.</strong>
          <span>Testing requires written permission and is limited to agreed targets, available access, and supported techniques. A named report and authorized tool-call check are part of the paid agreed scope, not a claim of guaranteed coverage or tests already performed. No certification, complete-coverage, security, or buyer-acceptance guarantee is implied.</span>
        </div>

        <div className="tooling-strip">
          <div>
            <span className="eyebrow">Free scanner, separate from the assessment</span>
            <h3>Run the handshake checks yourself first.</h3>
            <p>
              The MIT-licensed mcp-authscan project is free on GitHub and PyPI for self-service handshake
              checks. The paid assessment adds a scoped, authorized tool-call check and a written report
              signed by the researcher; actual coverage depends on the agreed scope and supported methods.
            </p>
          </div>
          <div className="tooling-links" aria-label="Scanner project links">
            <a className="text-link" href="https://github.com/LHMisme420/mcp-authscan" target="_blank" rel="noopener noreferrer">mcp-authscan on GitHub</a>
            <a className="text-link" href="https://pypi.org/project/mcp-authscan/" target="_blank" rel="noopener noreferrer">mcp-authscan on PyPI</a>
            <Link className="text-link" href="/sample-assessment">View synthetic sample report</Link>
          </div>
        </div>
      </div>
    </section>
  );
}

export function AssessmentMethodology() {
  return (
    <section className="landing-section commercial-section" id="methodology">
      <div className="wrap">
        <div className="section-head">
          <div>
            <span className="eyebrow">Method &amp; evidence</span>
            <h2>How the report stands up.</h2>
          </div>
          <p>
            A report is a claim by someone with an interest in it being believed. It should carry enough
            inspectable evidence for another party to question and compare.
          </p>
        </div>
        <div className="method-list">
          <article className="method-item">
            <span className="method-index">01</span>
            <div><h3>Permission and scope before testing</h3><p>Written authorization and the permitted targets and actions are agreed before any test request. Out-of-scope activity is not performed.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">02</span>
            <div><h3>Handshake checks and authorized tool calls</h3><p>The free scanner checks the handshake. Paid work adds an authorized tool-call check when included in the agreed scope and supported by the target and available access.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">03</span>
            <div><h3>Observed evidence, not implication</h3><p>Findings tie to observed request and response evidence. A response that demonstrates neither presence nor absence is not reported as a pass.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">04</span>
            <div><h3>A hash and a comparison another party can challenge</h3><p>The report carries a hash over the graded content. With authorization, a second party can rerun the same probe set and compare. The comparison outcomes are MATCH, DIVERGENCE, and NOT REPRODUCIBLE. These names describe comparison methodology, not an implemented one-click comparison UI. They do not establish which result is correct; a divergence can be caught and examined.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">05</span>
            <div><h3>Limits stated plainly</h3><p>An assessment is bounded by its scope and method: it cannot establish full coverage or guarantee safety or buyer acceptance. Evidence is redacted to avoid exposing secrets.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">06</span>
            <div><h3>Retest means a separate observed result</h3><p>One retest is part of the agreed offer. When requested after remediation, it checks agreed criteria and records the result; it is not implied to have happened in advance.</p></div>
          </article>
        </div>
        <div className="status-key" aria-label="Assessment verdict definitions">
          <span>PASS · demonstrated</span>
          <span className="status-fail">FAIL · absent or misconfigured</span>
          <span className="status-not-observed">NOT_OBSERVED · inconclusive</span>
          <span className="status-excluded">EXCLUDED · prerequisite unmet</span>
          <span className="status-excluded">NOT_IMPLEMENTED · not built</span>
        </div>
      </div>
    </section>
  );
}

export function AssessmentContact() {
  return (
    <section className="landing-section commercial-section" id="contact">
      <div className="wrap">
        <div className="contact-panel">
          <div>
            <span className="eyebrow">Start with the scope</span>
            <h2>Request an Assessment</h2>
            <p>
              Email the target description, who can authorize testing, and the scope you have in
              mind. Do not include credentials, tokens, or other secrets. Written permission is
              required before testing.
            </p>
            <a className="contact-mail" href={assessmentMailto}>{assessmentEmail}</a>
          </div>
          <div className="contact-actions">
            <a className="button" href={assessmentMailto}>Email us to request an assessment</a>
            <small>Opens an email draft. You must send it; this website submits nothing.</small>
          </div>
        </div>
      </div>
    </section>
  );
}
