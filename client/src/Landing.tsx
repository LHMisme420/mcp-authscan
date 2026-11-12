import { Link } from 'wouter';
import './commercial.css';
import { assessmentMailto, AssessmentContact, AssessmentMethodology, AssessmentServices } from './AssessmentSections';

export default function Landing() {
  return (
    <div className="landing app-shell">
      <header className="wrap landing-nav">
        <Link href="/" className="brand" aria-label="MCP AuthScan home">
          <img src="/logo.svg" alt="" />
          <span><span className="commercial-brand-name">MCP AuthScan</span><span className="commercial-brand-subtitle">Independent security assessment</span></span>
        </Link>
        <nav className="commercial-nav-links" aria-label="Main navigation">
          <a href="#assessments">Assessments</a>
          <a href="#methodology">Methodology</a>
          <a href="#contact">Contact</a>
          <Link href="/sample-assessment">Sample</Link>
        </nav>
        <nav className="nav-actions" aria-label="Workspace account">
          <Link href="/sign-in" className="button quiet">Sign in</Link>
          <Link href="/sign-up" className="button small">Create account</Link>
        </nav>
      </header>

      <main>
        <section className="wrap hero">
          <div className="hero-copy">
            <span className="eyebrow">Independent MCP security assessment</span>
            <h1>Independent MCP <span>security assessments.</span></h1>
            <p>
              Paid, scoped human security reviews for teams deploying MCP servers. Get a written
              report that distinguishes observed findings from exclusions and unanswered questions.
            </p>
            <div className="hero-ctas">
              <a href={assessmentMailto} className="button">Request an Assessment <span aria-hidden="true">→</span></a>
              <Link href="/sample-assessment" className="button secondary">View Sample Assessment</Link>
            </div>
            <div className="commercial-promise">
              Written permission and scope come first. An assessment is bounded—not a certification,
              a promise of full coverage, or a safety guarantee.
            </div>
            <div className="hero-note">No testing before written authorization</div>
          </div>
          <div className="hero-art" aria-label="Illustration representing an MCP security review, not a finding or assessment result" role="img">
            <div className="scan-orbit" />
            <div className="scan-core">
              <div className="core-mark" aria-hidden="true">
                <svg width="25" height="25" viewBox="0 0 24 24" fill="none"><path d="M12 3 4.5 6v5.5c0 4.5 3.2 7.7 7.5 9.5 4.3-1.8 7.5-5 7.5-9.5V6L12 3Z" stroke="currentColor" strokeWidth="1.6"/><path d="M12 8v5m0 3h.01" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"/></svg>
              </div>
              <p className="core-label">Review concept</p>
              <div className="core-value">MCP server</div>
              <div className="core-bars" aria-hidden="true"><i /><i /><i /></div>
            </div>
            <div className="float-tag one"><span className="signal" />Observed evidence</div>
            <div className="float-tag two"><span className="signal green" />Scope matters</div>
            <span className="commercial-art-note">Illustration only. Not a scan result or assessment finding.</span>
          </div>
        </section>

        <section className="trust-band" aria-label="Assessment principles">
          <div className="wrap trust-band-inner">
            <div className="trust-note"><span className="signal green" /><span><b>Written scope</b> before testing</span></div>
            <div className="trust-note"><span className="signal" /><span><b>Evidence-led</b> written report</span></div>
            <div className="trust-note"><span className="signal green" /><span><b>Limits stated</b> alongside results</span></div>
          </div>
        </section>

        <AssessmentServices />
        <AssessmentMethodology />

        <section className="landing-section">
          <div className="wrap">
            <div className="section-head">
              <div><span className="eyebrow">A separate workspace</span><h2>Self-service scanning for your own review workflow.</h2></div>
              <p>The workspace is a software offering. It is separate from an independent assessment and does not include one.</p>
            </div>
            <div className="workflow">
              <div className="workflow-main">
                <span className="eyebrow">MCP AuthScan workspace</span>
                <h3>Run checks. Review what came back.</h3>
                <p>The workspace brings together scanner results and finding details for teams assessing systems they are authorized to test.</p>
                <div className="workflow-list">
                  <div className="workflow-item"><b>01</b><span>Submit a server URL you are authorized to test.</span></div>
                  <div className="workflow-item"><b>02</b><span>Review scan status, severity, and remediation guidance.</span></div>
                  <div className="workflow-item"><b>03</b><span>Return to scan history and organization-level records.</span></div>
                </div>
              </div>
              <div className="workflow-aside" aria-label="Workspace data categories">
                <div className="readout"><span>Findings</span><strong>By severity</strong></div>
                <div className="readout"><span>History</span><strong>Recent scan runs</strong></div>
                <div className="readout"><span>Workflow</span><strong className="good">Team review</strong></div>
                <div className="readout"><span>Authorization</span><strong>Use only with permission</strong></div>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section">
          <div className="wrap statement">
            <div><span className="eyebrow">Your security workspace</span></div>
            <div>
              <blockquote>Scan, review, and collaborate.</blockquote>
              <p>Create an account to use the separate self-service workspace for MCP scans and team review.</p>
              <div className="hero-ctas">
                <Link href="/sign-up" className="button">Create your account</Link>
                <Link href="/sign-in" className="button secondary">Already have an account?</Link>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section plan-section">
          <div className="wrap">
            <div className="section-head">
              <div><span className="eyebrow">Workspace features</span><h2>Review findings and automate your scans.</h2></div>
              <p>Workspace features are available after sign-in, with organization-scoped access. They are not part of an independent assessment.</p>
            </div>
            <div className="plan-table">
              <div className="plan-column free-plan">
                <div className="plan-column-head"><span className="eyebrow">Scan and review</span><strong>Investigate</strong><span>For individual review</span></div>
                <ul>
                  <li>Unlimited manual MCP scans</li>
                  <li>Full scan and finding history</li>
                  <li>Create and review finding records</li>
                  <li>Organization-scoped findings</li>
                </ul>
              </div>
              <div className="plan-column pro-plan">
                <div className="plan-column-head"><span className="eyebrow">Collaborate and automate</span><strong>Coordinate</strong><span>For team workflows</span></div>
                <ul>
                  <li>Unlimited scans and history</li>
                  <li>Programmatic scan API access</li>
                  <li>Automated scan scheduling</li>
                  <li>Up to 5 seats, including the owner</li>
                </ul>
              </div>
              <div className="plan-column weekly-plan">
                <div className="plan-column-head"><span className="eyebrow">Separate recurring workspace offering</span><strong>Weekly re-checks</strong><span>$49 a month</span></div>
                <ul>
                  <li>Scheduled re-checks</li>
                  <li>History with drift between runs</li>
                  <li>SARIF export</li>
                  <li>Workspace subscription only; no independent assessment included</li>
                </ul>
                <a className="button" href="https://buy.stripe.com/aFabJ1dK2axT4j664E7Vm00" target="_blank" rel="noopener noreferrer" aria-label="Get weekly re-checks (opens in a new tab)">Get weekly re-checks</a>
              </div>
            </div>
            <p className="plan-footnote">Only the workspace owner manages invitations and API tokens. The existing $49/month link is for this separate recurring workspace offer.</p>
          </div>
        </section>
        <AssessmentContact />
      </main>

      <footer className="wrap landing-footer">
        <Link href="/" className="brand" aria-label="MCP AuthScan home"><img src="/logo.svg" alt="" /><span className="commercial-brand-name">MCP AuthScan</span></Link>
        <span>Independent assessment. Explicit scope. No certification claims.</span>
      </footer>
    </div>
  );
}
