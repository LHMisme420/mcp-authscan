import { Link } from 'wouter';
import PublicSiteLayout from './PublicSiteLayout';
import { AssessmentMethodology } from './AssessmentSections';

export default function Assessments() {
  return (
    <PublicSiteLayout className="assessments-page">
      <section className="wrap public-page-heading">
        <span className="eyebrow">MCP AuthScan · Independent technical review</span>
        <h1>Independent MCP Security Assessments</h1>
        <p>Evidence-backed security verification for organizations deploying Model Context Protocol infrastructure.</p>
        <p>
          MCP AuthScan combines automated security checks with independent technical review to assess
          authentication, authorization, OAuth configuration, and supported MCP protocol security behavior.
        </p>
        <div className="assessment-points" aria-label="Assessment principles">
          <span>Written authorization before testing</span>
          <span>Reproducible evidence</span>
          <span>Independent validation</span>
          <span>Transparent severity</span>
          <span>Limitations documented</span>
          <span>Remediation guidance</span>
        </div>
      </section>

      <section className="landing-section commercial-section" aria-label="Assessment packages">
        <div className="wrap">
          <div className="commercial-grid">
            <article className="commercial-offer">
              <div className="offer-topline"><span>Package A · focused scope</span><strong className="offer-price">$1,750</strong></div>
              <h2 className="commercial-offer-title">MCP Server Security Verification</h2>
              <p>Independent verification of one authorized MCP server and its supported security behavior.</p>
              <ul className="package-includes">
                <li>One authorized MCP server</li>
                <li>Authentication and supported protocol-security checks</li>
                <li>Manual validation of significant scanner findings</li>
                <li>Evidence-backed assessment report</li>
                <li>Severity rationale and remediation guidance</li>
                <li>JSON and SARIF output where applicable</li>
              </ul>
              <div className="offer-bottom">
                <Link className="button" href="/request-assessment?package=verification">Request Assessment</Link>
                <span>Scope and authorization approval before payment or testing</span>
              </div>
            </article>
            <article className="commercial-offer expanded">
              <div className="offer-topline"><span>Package B · expanded review</span><strong className="offer-price">$3,500</strong></div>
              <h2 className="commercial-offer-title">Comprehensive MCP Security Assessment</h2>
              <p>A broader, mutually agreed security review with one remediation retest.</p>
              <ul className="package-includes">
                <li>Expanded, mutually agreed MCP security testing scope</li>
                <li>Authentication and authorization boundary review</li>
                <li>OAuth and protocol configuration analysis where applicable</li>
                <li>Manual investigation of significant findings</li>
                <li>Executive and technical assessment report</li>
                <li>Remediation recommendations</li>
                <li>One remediation retest</li>
              </ul>
              <div className="offer-bottom">
                <Link className="button" href="/request-assessment?package=comprehensive">Request Assessment</Link>
                <span>Retest stays within separately agreed criteria and scope</span>
              </div>
            </article>
          </div>
          <div className="package-notice">
            Actual testing is limited to agreed scope, available credentials, supported techniques, and written authorization.
            These services are independent technical assessments—not certification, regulatory compliance, a promise of complete
            vulnerability coverage, or a guarantee of security. Engagement scope and authorization are approved before payment
            and testing; these packages do not use automatic checkout.
          </div>
          <div className="tooling-strip">
            <div>
              <span className="eyebrow">For enterprise security reviews</span>
              <h3>Evidence and limits belong in the same report.</h3>
              <p>Reports document observations, transparent severity classifications, exclusions, and remediation recommendations to support technical and enterprise security reviews.</p>
              <p>The free open-source PyPI scanner provides automated self-service checks. A paid independent assessment adds a separately scoped human review and validation; a VATA workspace subscription does not include this assessment service.</p>
            </div>
            <div className="tooling-links">
              <Link className="text-link" href="/sample-assessment">Read the synthetic sample</Link>
              <Link className="text-link" href="/request-assessment">Discuss a scope</Link>
            </div>
          </div>
        </div>
      </section>

      <AssessmentMethodology />

      <section className="landing-section commercial-section">
        <div className="wrap credibility-panel">
          <span className="eyebrow">Research practice</span>
          <h2>Security evidence, not security theater.</h2>
          <p>
            MCP AuthScan research separates confirmed observations from inconclusive results and records how each
            conclusion was reached. Independent validation contextualizes scanner output; it does not turn a bounded
            review into a certification or guarantee.
          </p>
          <ul className="credibility-list">
            <li><b>01</b><span>Versioned probe sets</span></li>
            <li><b>02</b><span>Separate severity calibration</span></li>
            <li><b>03</b><span>Confirmed observations versus inconclusive results</span></li>
            <li><b>04</b><span>Explicitly excluded tests</span></li>
            <li><b>05</b><span>Reproducibility comparisons</span></li>
            <li><b>06</b><span>Content-based evidence fingerprints</span></li>
            <li><b>07</b><span>Transparent coverage limitations</span></li>
          </ul>
          <div className="tooling-links" style={{ marginTop: 20 }}>
            <a className="text-link" href="https://pypi.org/project/mcp-authscan/" target="_blank" rel="noopener noreferrer">Genuine PyPI package</a>
            <a className="text-link" href="https://github.com/LHMisme420/mcp-authscan" target="_blank" rel="noopener noreferrer">Public research repository</a>
          </div>
        </div>
      </section>
    </PublicSiteLayout>
  );
}
