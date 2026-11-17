import PublicSiteLayout from './PublicSiteLayout';

// Owner-frozen wording: do not edit for tone. Any copy change requires the
// owner's review and an explicit update to the approved-copy regression fixture.
export default function SampleReport() {
  return (
    <PublicSiteLayout className="sample-page">
      <div className="wrap">
        <article id="sample-report-text" className="sample-section" style={{ overflowWrap: 'anywhere' }}>
          <h1>SAMPLE ASSESSMENT REPORT</h1>
          <p>AgentPayStore, redacted</p>
          <p style={{ overflowWrap: 'anywhere' }}>
            A real report from an authorized engagement, published with the operator's permission. The client name is used with permission. Nothing here exposes credentials, tokens or internal infrastructure.
          </p>
          <h2>SCOPE</h2>
          <p>Target: agentpaystore.com/book/mcp</p>
          <p>Authorized by: Shawn Lippert, written authorization, 16 November 2026</p>
          <p>Assessed by: Leroy H. Mason</p>
          <p>Scanner: mcp-authscan 1.1.24, probe set 2026.11.16.2, severity calibration 2026.11.07.1</p>
          <p>Mode: live endpoint testing from outside, no credential issued</p>
          <p>Not tested: source code, dependency CVEs, secrets in history, prompt injection, tool poisoning, audit telemetry.</p>
          <h2>RESULT</h2>
          <p>VERDICT HIGH. One finding.</p>
          <p>
            ZERO-AUTH, unauthenticated MCP endpoint. The server completed the handshake with no credential and listed 15 tools. Severity basis, in the report's own words: zero-auth, 15 tools listed with no authentication, tool-call probe not run.
          </p>
          <h2>WHAT COULD NOT BE TESTED, AND WHY</h2>
          <p>One probe passed. Fifteen were excluded. Coverage, 1 of 1 testable probe.</p>
          <p>
            Twelve exclusions share a single reason: no authorization server was discovered, so the issuer, resource binding, token caching, token CORS, JWKS, password grant, PKCE, redirect URI, client auth, cross-tenant and audience probes were never sent. Rate limiting was excluded for want of an authorised request budget. Sibling transport and origin parity were excluded on a 404.
          </p>
          <p>
            Those exclusions are the finding seen from the other side. A server with no authorization server cannot be tested for token handling, because there is no token.
          </p>
          <h2>REPEATABILITY</h2>
          <p>Report hash: e08ed15790a437ed93573757e377f153aedd043a430cf1e3de93ddea514063e5</p>
          <p>
            hash computed over authorization, scan mode, probe status, findings, and the exit contract, condition, code and fail-on; excludes run start time, elapsed time, server-varying headers, tool version, scope statement, client registration block, tools digest, and finding detail text.
          </p>
          <p>
            Outside the hash, and marked as such: the tools digest, 15 tools, d66a10a3c4d4e66a041476f3598920092a915a34c33c61083609440c1242d607. It records what this session received, not a verdict.
          </p>
          <p>
            A second party re-runs the same probe set on the same target. MATCH means identical graded content. DIVERGENCE names the differing fields rather than calling the tool wrong. NOT REPRODUCIBLE means the hash cannot be recomputed.
          </p>
          <h2>WHAT THIS DOES NOT CLAIM</h2>
          <p>Not a certification. Not a guarantee of security. No claim that the scanner is right; the point is that the claim is inspectable. Acceptance is the buyer's decision.</p>
          <p>
            This server has not been retested. An assessment includes one retest of the same endpoint after fixes, and the two hashes side by side are the before and after.
          </p>
          <div className="hero-ctas">
            <a className="button" href="https://buy.stripe.com/8x2bJ18pI9tP9Dq64E7Vm01">Single-server assessment — $1,750</a>{' '}
            <a className="button secondary" href="https://buy.stripe.com/dRmfZh35o6hDcPCakU7Vm02">Full assessment — $3,500</a>
          </div>
        </article>
      </div>
    </PublicSiteLayout>
  );
}
