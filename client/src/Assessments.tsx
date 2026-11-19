import { Link } from 'wouter';
import PublicSiteLayout from './PublicSiteLayout';
import { AssessmentMethodology, assessmentEmailFor } from './AssessmentSections';
import PricingTiers from './PricingTiers';

export default function Assessments() {
  return (
    <PublicSiteLayout className="assessments-page">
      <section className="wrap public-page-heading">
        <span className="eyebrow">MCP AuthScan · Independent technical review</span>
        <h1>Independent MCP Security Assessments</h1>
        <p>A written, scoped review of an MCP server&apos;s authorization surface, signed by the researcher who ran it.</p>
        <p>
          Leroy H. Mason is an independent AI security researcher and credited reporter on published MCP
          security advisories. A report may support a buyer&apos;s review, but acceptance is decided by the buyer.
        </p>
        <div className="assessment-points" aria-label="Assessment principles">
          <span>Written authorization before testing</span>
          <span>Evidence that can be inspected</span>
          <span>Hash over graded report content</span>
          <span>Comparison outcomes stated</span>
          <span>Scope limitations documented</span>
          <span>Remediation guidance</span>
        </div>
      </section>

      <section className="landing-section commercial-section" aria-label="Assessment packages">
        <div className="wrap">
          <PricingTiers emailHref={assessmentEmailFor()} checkout />
          <div className="package-notice">
            Testing requires written authorization and is limited to agreed targets, available access, and supported techniques.
            The named report and authorized tool-call check are part of the paid agreed scope, not guaranteed coverage or tests
            already performed. These are independent technical assessments—not certification, complete vulnerability coverage,
            a guarantee of security, or a guarantee of buyer acceptance.
          </div>
          <div className="tooling-strip">
            <div>
              <span className="eyebrow">For enterprise security reviews</span>
              <h3>Start with the free handshake checks.</h3>
              <p>The MIT-licensed mcp-authscan scanner is available on GitHub and PyPI for buyers to run themselves. The free scanner checks the handshake; paid work adds an authorized tool-call check within agreed, supported scope and a named written report.</p>
              <p>A report carries a hash over its graded content. With authorization, a second party can rerun the same probe set and compare. MATCH, DIVERGENCE, and NOT REPRODUCIBLE describe comparison methodology, not an implemented one-click comparison UI. The method does not claim which result is correct; it can help catch a difference.</p>
            </div>
            <div className="tooling-links">
              <a className="text-link" href="https://github.com/LHMisme420/mcp-authscan" target="_blank" rel="noopener noreferrer">mcp-authscan on GitHub</a>
              <a className="text-link" href="https://pypi.org/project/mcp-authscan/" target="_blank" rel="noopener noreferrer">mcp-authscan on PyPI</a>
              <Link className="text-link" href="/sample-report">Read the sample report</Link>
              <Link className="text-link" href="/request-assessment">Discuss a scope</Link>
            </div>
          </div>
        </div>
      </section>

      <AssessmentMethodology />

      <section className="landing-section commercial-section">
        <div className="wrap credibility-panel">
          <span className="eyebrow">Research practice</span>
          <h2>Who signs the report: Leroy H. Mason.</h2>
          <p>
            Independent AI security researcher, credited reporter on published MCP security advisories. Reports separate
            observed findings from inconclusive results and state how each conclusion was reached. This does not establish
            complete coverage, guarantee correctness, or promise buyer acceptance.
          </p>
          <ul className="credibility-list">
            <li><b>01</b><span>Written authorization and agreed scope</span></li>
            <li><b>02</b><span>Observed findings versus inconclusive results</span></li>
            <li><b>03</b><span>Hash over graded report content</span></li>
            <li><b>04</b><span>Comparison labels: MATCH, DIVERGENCE, NOT REPRODUCIBLE</span></li>
            <li><b>05</b><span>Retest result recorded only when performed</span></li>
            <li><b>06</b><span>Explicit exclusions and coverage limits</span></li>
          </ul>
          <div className="tooling-links" style={{ marginTop: 20 }}>
            <a className="text-link" href="https://pypi.org/project/mcp-authscan/" target="_blank" rel="noopener noreferrer">mcp-authscan on PyPI</a>
            <a className="text-link" href="https://github.com/LHMisme420/mcp-authscan" target="_blank" rel="noopener noreferrer">mcp-authscan on GitHub</a>
          </div>
        </div>
      </section>
    </PublicSiteLayout>
  );
}
