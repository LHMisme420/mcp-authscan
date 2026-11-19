import { Link } from 'wouter';
import PublicSiteLayout from './PublicSiteLayout';
import { assessmentEmailFor } from './AssessmentSections';
import PricingTiers from './PricingTiers';
import './commercial.css';

export default function Landing({ homepageVariant = false }: { homepageVariant?: boolean }) {
  return (
    <PublicSiteLayout className="landing">
      <section className="wrap hero">
        <div className="hero-copy">
          {homepageVariant ? (
            <PricingTiers
              emailHref={assessmentEmailFor()}
              homepageVariant
              afterCards={
                <>
                <section aria-labelledby="home-sample-report-title" style={{ overflowWrap: 'anywhere' }}>
                  <h2 id="home-sample-report-title">Sample report</h2>
                  <p>A real run, published with the operator's agreement and redacted, from a free scan rather than a paid assessment.</p>
                  <dl>
                    <dt>Target:</dt><dd>agentpaystore.com/book/mcp</dd>
                    <dt>Server:</dt><dd>agentpay-bookings 1.0.0</dd>
                    <dt>Tool:</dt><dd>development build of mcp-authscan (reported 1.1.24)</dd>
                    <dt>Probe set:</dt><dd>2026.11.16.2, in no release; see the reproducible 1.1.25 sample on the sample report page</dd>
                    <dt>Verdict:</dt><dd>HIGH</dd>
                    <dt>Findings:</dt><dd>1</dd>
                    <dt>Coverage:</dt><dd>1 of 1 testable</dd>
                    <dt>Excluded:</dt><dd>15</dd>
                    <dt>Hash:</dt><dd>e08ed15790a437ed93573757e377f153aedd043a430cf1e3de93ddea514063e5</dd>
                  </dl>
                  <p>Fifteen probes returned no verdict on this target. Twelve of them share one reason: the server publishes no authorization server, so the OAuth discovery, issuer, token and client-registration checks had nothing to test against. They are recorded as excluded, not passed, and the report says so on its face.</p>
                  <p>The hash covers graded content only, the probe results, findings, severities and the basis for each severity, and leaves out timestamps and server-varying headers. A second party can re-run the same probe set on the same target and either recompute the same hash or name the fields that differ.</p>
                  <a href="/sample-report" className="button secondary">View the sample report</a>
                </section>
                <div className="scope-closing-block">
                  <p>Send the server URL and who authorizes the test. Scope and written authorization are agreed by email before anything is tested. Do not include credentials, tokens or secrets in email.</p>
                  <div className="hero-ctas">
                    <a href="/scope" className="button">Start a scope request</a>
                    <a href="/sample-report" className="button secondary">See a sample report</a>
                    <a className="button secondary" href={assessmentEmailFor()}>Email Leroy</a>
                  </div>
                </div>
                </>
              }
              renderLead={(openForm) => (
                <>
                  <h1>The connector is what gets breached.</h1>
                  <p>In late October 2026 a <a href="https://www.mittwald.de/blog/mittwald/sicherheitsvorfall-am-mcp-server" target="_blank" rel="noopener noreferrer">German hosting company</a> was breached through the MCP server it built so customers could attach an AI assistant to their console. The attacker did not break the console, they broke the connector in front of it, and <a href="https://therecord.media/cyberattack-germany-ai-mittwald" target="_blank" rel="noopener noreferrer">eight days in they had reached 56 customer projects.</a></p>
                  <p>An independent assessment of your MCP server records how it handles sign-in, what it exposes without a credential, and what changes when you ship a fix. The report carries a hash a second party can recompute by re-running the same checks on the same server, so your buyer can verify it instead of trusting it.</p>
                  <p>One server, 1750 dollars. Full assessment with one retest, 3500 dollars.</p>
                  <button className="button" type="button" onClick={openForm}>Start an assessment</button>
                </>
              )}
            />
          ) : (
            <>
              <span className="eyebrow">Independent MCP security assessment</span>
              <h1>MCP security assessment your buyer&apos;s review will accept.</h1>
              <p>An independent, written review of your MCP server&apos;s authorization surface, signed by the researcher who ran it.</p>
              <PricingTiers
                emailHref={assessmentEmailFor()}
                afterCards={
                  <div>
                    <p>Send the server URL and who authorizes the test. Scope and written authorization are agreed by email before anything is tested. Do not include credentials, tokens or secrets in email.</p>
                    <div className="hero-ctas">
                      <Link href="/scope" className="button">Start a scope request</Link>
                      <a className="button secondary" href={assessmentEmailFor()}>Email Leroy</a>
                      <Link href="/sample-report" className="button secondary">See a sample report</Link>
                    </div>
                  </div>
                }
              />
            </>
          )}
          <p className="hero-note">{homepageVariant
            ? 'A report may support a buyer review; acceptance is up to the buyer.'
            : 'Scope and written authorization are agreed before testing. A report may support a buyer review; acceptance is up to the buyer.'}</p>
          <div className="hero-ctas">
            <a className="button" href={assessmentEmailFor()}>Email us to request an assessment</a>
            <Link href="/sign-in" className="button secondary">Workspace sign in</Link>
          </div>
          {!homepageVariant && <div className="hero-note">No credentials, tokens, passwords, or other secrets in email.</div>}
        </div>
        <div className="hero-art" aria-label="Illustration of an MCP security review" role="img">
          <div className="scan-orbit" />
          <div className="scan-core">
            <div className="core-mark" aria-hidden="true">
              <svg width="25" height="25" viewBox="0 0 24 24" fill="none"><path d="M12 3 4.5 6v5.5c0 4.5 3.2 7.7 7.5 9.5 4.3-1.8 7.5-5 7.5-9.5V6L12 3Z" stroke="currentColor" strokeWidth="1.6"/><path d="M12 8v5m0 3h.01" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"/></svg>
            </div>
            <p className="core-label">Independent review</p>
            <div className="core-value">MCP server</div>
            <div className="core-bars" aria-hidden="true"><i /><i /><i /></div>
          </div>
          <div className="float-tag one"><span className="signal" />Handshake checks</div>
          <div className="float-tag two"><span className="signal green" />Written evidence</div>
        </div>
      </section>

      <section className="trust-band">
        <div className="wrap trust-band-inner">
          <div className="trust-note"><span className="signal green" /><span><b>Named researcher</b> signs the report</span></div>
          <div className="trust-note"><span className="signal" /><span><b>Written authorization</b> before testing</span></div>
          <div className="trust-note"><span className="signal green" /><span><b>Scope and limitations</b> stated plainly</span></div>
        </div>
      </section>

      <section className="landing-section" id="report-method">
        <div className="wrap">
          <div className="section-head">
            <div><span className="eyebrow">Evidence and repeatability</span><h2>How the report stands up</h2></div>
            <p>A report is a claim by someone with an interest in it being believed. The record should make that claim inspectable.</p>
          </div>
          <p>The report carries a hash over the graded content. With written authorization, a second party can re-run the same probe set and compare. The comparison is recorded as MATCH, DIVERGENCE or NOT REPRODUCIBLE.</p>
          <p className="plan-footnote">The method does not claim the tool or report is right; it makes inconsistencies easier to catch. Reproduction depends on the agreed scope, available access, and supported techniques.</p>
        </div>
      </section>

      <section className="service-teaser" aria-labelledby="service-teaser-title">
        <div className="wrap service-teaser-inner">
          <div>
            <span className="eyebrow">Who signs the report</span>
            <h2 id="service-teaser-title">Leroy H. Mason</h2>
            <p>Independent AI security researcher, credited reporter on published MCP security advisories. The assessment is a scoped technical review, not a certification, guarantee of security, or promise of buyer acceptance.</p>
          </div>
          <div className="service-teaser-actions">
            <a className="button" href={assessmentEmailFor()}>Email us to request an assessment</a>
            <Link className="button secondary" href="/assessments">Assessment details</Link>
            <Link className="button secondary" href="/blast-radius">Blast Radius</Link>
            <Link className="text-link" href="/request-assessment">No email app? See email instructions</Link>
          </div>
        </div>
      </section>

      <section className="landing-section plan-section" id="free-scanner">
        <div className="wrap">
          <div className="section-head">
            <div><span className="eyebrow">Free, open-source checks</span><h2>Run the handshake checks yourself first.</h2></div>
            <p>The MIT-licensed mcp-authscan is available on GitHub and PyPI. Its free scanner checks the handshake; paid work adds an authorized tool-call check and a named written report within the agreed scope.</p>
          </div>
          <div className="tooling-strip">
            <div>
              <span className="eyebrow">Inspect the tool</span>
              <h3>Start with the same public checks.</h3>
              <p>The paid check is performed only with written authorization and where the agreed scope and supported techniques allow it. Neither an authorized tool-call check nor a particular coverage outcome is guaranteed before scope is agreed; no test is represented as already run.</p>
            </div>
            <div className="tooling-links" aria-label="Scanner project links">
              <pre className="free-run-command"><code>pip install mcp-authscan{"\n"}mcp-authscan https://api.example.com/mcp --authorized-by &quot;Your Name&quot; --auth-basis &quot;written consent&quot; --contact &quot;you@example.com&quot;</code></pre>
              <p className="release-anchor">Current release: mcp-authscan 1.1.25, probe set 2026.11.16.1. Wheel sha256 <code>b0b4f2d0456b0aaee95913b5c4f53c056af406477f960706e975df2b81183be5</code>. Compare it: <code>pip download --no-deps mcp-authscan==1.1.25</code>, then <code>sha256sum</code> the wheel.</p>
              <a className="text-link" href="https://pypi.org/project/mcp-authscan/" target="_blank" rel="noopener noreferrer">mcp-authscan on PyPI</a>
              <Link className="text-link" href="/sample-report">View sample report</Link>
              <Link className="text-link assessment-discovery-link" href="/assessment">An MCP AuthScan assessment</Link>
            </div>
          </div>
        </div>
      </section>

      <section className="landing-section">
        <div className="wrap statement">
          <div><span className="eyebrow">The existing workspace</span></div>
          <div>
            <blockquote>Run checks. Keep the findings in view.</blockquote>
            <p>The MCP AuthScan workspace remains available for teams running authorized scans, reviewing their results, and using the existing scan API.</p>
            <div className="hero-ctas">
              <Link href="/sign-up" className="button">Create your account</Link>
              <Link href="/sign-in" className="button secondary">Sign in</Link>
            </div>
          </div>
        </div>
      </section>
    </PublicSiteLayout>
  );
}
