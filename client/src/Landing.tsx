import { Link } from 'wouter';

export default function Landing() {
  return (
    <div className="landing app-shell">
      <header className="wrap landing-nav">
        <Link href="/" className="brand" aria-label="VATA home"><img src="/logo.svg" alt="" /><span className="brand-word">VATA</span></Link>
        <nav className="nav-actions" aria-label="Main navigation">
          <Link href="/sign-in" className="button quiet">Sign in</Link>
          <Link href="/sign-up" className="button small">Create account</Link>
        </nav>
      </header>

      <main>
        <section className="wrap hero">
          <div className="hero-copy">
            <span className="eyebrow">MCP security review workspace</span>
            <h1>See what an MCP server is <span>allowed to do.</span></h1>
            <p>VATA scans MCP endpoints for authorization findings, then gives your team a clear place to review risk, compliance scoring, and scan history.</p>
            <div className="hero-ctas">
              <Link href="/sign-up" className="button">Open your workspace <span aria-hidden="true">→</span></Link>
              <Link href="/sign-in" className="button secondary">Sign in</Link>
            </div>
            <div className="hero-note">For teams testing systems they are authorized to assess</div>
          </div>
          <div className="hero-art" aria-label="Illustration of a security scan in progress" role="img">
            <div className="scan-orbit" />
            <div className="scan-core">
              <div className="core-mark" aria-hidden="true">
                <svg width="25" height="25" viewBox="0 0 24 24" fill="none"><path d="M12 3 4.5 6v5.5c0 4.5 3.2 7.7 7.5 9.5 4.3-1.8 7.5-5 7.5-9.5V6L12 3Z" stroke="currentColor" strokeWidth="1.6"/><path d="M12 8v5m0 3h.01" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"/></svg>
              </div>
              <p className="core-label">Authorization review</p>
              <div className="core-value">MCP server</div>
              <div className="core-bars" aria-hidden="true"><i /><i /><i /></div>
            </div>
            <div className="float-tag one"><span className="signal" />Endpoint check</div>
            <div className="float-tag two"><span className="signal green" />Findings review</div>
          </div>
        </section>

        <section className="trust-band">
          <div className="wrap trust-band-inner">
            <div className="trust-note"><span className="signal green" /><span><b>Organization-scoped</b> findings and scan history</span></div>
            <div className="trust-note"><span className="signal" /><span><b>Full history</b> available in your workspace</span></div>
            <div className="trust-note"><span className="signal green" /><span><b>Cookie-based</b> authenticated workspace</span></div>
          </div>
        </section>

        <section className="landing-section">
          <div className="wrap">
            <div className="section-head">
              <div><span className="eyebrow">A focused workflow</span><h2>From endpoint to evidence, without losing the thread.</h2></div>
              <p>Keep the steps visible: scan an authorized target, inspect the returned findings, and follow the organization’s compliance score over time.</p>
            </div>
            <div className="workflow">
              <div className="workflow-main">
                <span className="eyebrow">One review surface</span>
                <h3>Know what was checked. Keep what came back.</h3>
                <p>VATA brings together the scanner’s results and the underlying finding details, so authorization issues can be reviewed in context.</p>
                <div className="workflow-list">
                  <div className="workflow-item"><b>01</b><span>Submit an MCP server URL you may test.</span></div>
                  <div className="workflow-item"><b>02</b><span>Review scan status, severity, and remediation guidance.</span></div>
                  <div className="workflow-item"><b>03</b><span>Return to scan history and organization-level signals.</span></div>
                </div>
              </div>
              <div className="workflow-aside" aria-label="Dashboard data categories">
                <div className="readout"><span>Findings</span><strong>By severity</strong></div>
                <div className="readout"><span>History</span><strong>Recent scan runs</strong></div>
                <div className="readout"><span>Compliance</span><strong className="good">Score included</strong></div>
                <div className="readout"><span>Authorization</span><strong>Review the evidence</strong></div>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-section">
          <div className="wrap statement">
            <div><span className="eyebrow">Your security workspace</span></div>
            <div>
              <blockquote>Scan, review, and collaborate.</blockquote>
              <p>Create an account to scan authorized MCP servers, review your findings, and work with your team. No payment setup is needed.</p>
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
              <p>All workspace features are available after sign-in, with organization-scoped access.</p>
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
            </div>
             <p className="plan-footnote">Only the workspace owner manages invitations and API tokens. No subscription or payment details are required.</p>
          </div>
        </section>
      </main>

      <footer className="wrap landing-footer">
        <div className="brand"><img src="/logo.svg" alt="" /><span className="brand-word">VATA</span></div>
        <span>Security findings belong to the organization that reviewed them.</span>
      </footer>
    </div>
  );
}
