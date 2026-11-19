import { Link } from 'wouter';

const contactSubject = 'MCP AuthScan independent assessment inquiry';
const contactBody = [
  'Hello, I would like to discuss an MCP AuthScan independent assessment.',
  '',
  'Name / organization:',
  'Target description (no secrets):',
  'Authorizing party:',
  'Desired scope:',
  '',
  'I can provide written authorization before any testing begins.',
].join('\n');

export const assessmentMailto = `mailto:lhmisme2011@gmail.com?subject=${encodeURIComponent(contactSubject)}&body=${encodeURIComponent(contactBody)}`;

export function AssessmentServices() {
  return (
    <section className="landing-section commercial-section" id="assessments">
      <div className="wrap">
        <div className="assessment-intro">
          <div>
            <span className="eyebrow">Independent, scoped review</span>
            <h2>Evidence you can act on. Limits you can see.</h2>
          </div>
          <p>
            MCP AuthScan offers paid independent security assessments for teams deploying MCP servers.
            A scoped human review produces a written report grounded in observed responses—not a
            certification, a safety guarantee, or a claim of complete coverage.
          </p>
        </div>

        <div className="commercial-grid">
          <article className="commercial-offer">
            <div className="offer-topline">
              <span>Single engagement</span>
              <strong className="offer-price">$1,750</strong>
            </div>
            <h3>MCP Server Security Verification</h3>
            <p>Focused independent verification of one authorized MCP server.</p>
            <ul className="package-includes">
              <li>Authentication and supported protocol-security checks</li>
              <li>Manual validation of significant scanner findings</li>
              <li>Evidence-backed assessment report</li>
              <li>Severity rationale and remediation guidance</li>
              <li>JSON and SARIF output where applicable</li>
            </ul>
            <div className="offer-bottom">
              <Link className="button" href="/request-assessment?package=verification">Request an Assessment</Link>
              <span>Scope and written authorization before testing</span>
            </div>
          </article>

          <article className="commercial-offer expanded">
            <div className="offer-topline">
            <span>Expanded assessment</span>
              <strong className="offer-price">$3,500</strong>
            </div>
            <h3>Comprehensive MCP Security Assessment</h3>
            <p>A broader mutually agreed MCP security review, including one remediation retest.</p>
            <ul className="package-includes">
              <li>Expanded, mutually agreed testing scope</li>
              <li>Authentication and authorization boundary review</li>
              <li>OAuth and protocol configuration analysis where applicable</li>
              <li>Manual investigation of significant findings</li>
              <li>Executive and technical assessment report</li>
              <li>Remediation recommendations and one retest</li>
            </ul>
            <div className="offer-bottom">
              <Link className="button" href="/request-assessment?package=comprehensive">Request an Assessment</Link>
              <span>Retest against agreed criteria only</span>
            </div>
          </article>
        </div>

        <div className="scope-caveat">
          <strong>Scope first.</strong>
          <span>Actual testing is limited to agreed scope, available credentials, supported techniques, and written authorization. No certification, compliance, complete-coverage, or security guarantee is implied.</span>
        </div>

        <div className="tooling-strip">
          <div>
            <span className="eyebrow">Self-service tool</span>
            <h3>The free scanner is not the independent assessment.</h3>
            <p>
              Run the free open-source PyPI scanner yourself for self-service checks. A paid
              assessment is a separately scoped human review with written evidence, findings, and
              stated limitations.
            </p>
          </div>
          <div className="tooling-links" aria-label="Scanner project links">
            <a className="text-link" href="https://pypi.org/project/mcp-authscan/" target="_blank" rel="noopener noreferrer">PyPI package</a>
            <a className="text-link" href="https://github.com/LHMisme420/mcp-authscan" target="_blank" rel="noopener noreferrer">GitHub source</a>
            <Link className="text-link" href="/sample-assessment">View sample report</Link>
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
            <h2>Say what the response showed—and what it did not.</h2>
          </div>
            <p>
              Versioned probes, separately calibrated severity, independent validation, and explicit
              exclusions keep the report tied to what was observed. The sample illustrates the format;
              it is not evidence about a real deployment.
            </p>
        </div>
        <div className="method-list">
          <article className="method-item">
            <span className="method-index">01</span>
            <div><h3>Permission and scope before testing</h3><p>Written authorization and the permitted targets and actions are agreed before any test request. Out-of-scope activity is not performed.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">02</span>
            <div><h3>Observed evidence, not implication</h3><p>Findings tie to observed request and response evidence. A response that demonstrates neither presence nor absence is not reported as a pass.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">03</span>
            <div><h3>Explicit verdicts and exclusions</h3><p>Each check is labeled PASS, FAIL, NOT_OBSERVED, or EXCLUDED; NOT_IMPLEMENTED may also apply. Exclusions name the missing prerequisite.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">04</span>
            <div><h3>Limits stated plainly</h3><p>An assessment is bounded by its scope and method: it cannot establish full coverage or guarantee safety. Evidence is redacted to avoid exposing secrets.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">05</span>
            <div><h3>Retest means a separate observed result</h3><p>When included and requested after remediation, a retest checks its agreed criteria and records the result. It is not implied to have happened in advance.</p></div>
          </article>
          <article className="method-item">
            <span className="method-index">06</span>
            <div><h3>What a content hash can verify</h3><p>Where a real report provides a content hash, its exact schema is explained. A hash can check content consistency; it does not prove who authored the report, that evidence is authentic, or that testing had complete coverage.</p></div>
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
            <a className="contact-mail" href={assessmentMailto}>lhmisme2011@gmail.com</a>
          </div>
          <div className="contact-actions">
              <Link className="button" href="/request-assessment">Request an Assessment</Link>
            <small>This opens your email client with a suggested subject and prompts. No information is submitted to this website.</small>
          </div>
        </div>
      </div>
    </section>
  );
}
