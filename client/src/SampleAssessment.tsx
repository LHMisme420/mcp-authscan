import { Link } from 'wouter';
import PublicSiteLayout from './PublicSiteLayout';
import { assessmentMailto } from './AssessmentSections';

export default function SampleAssessment() {
  return (
    <PublicSiteLayout className="sample-page" footerNote="SYNTHETIC SAMPLE · No client · No real assessment · No requests sent">
      <div className="wrap">
        <section className="sample-header">
          <span className="eyebrow">Public report format example</span>
          <h1>MCP server security assessment</h1>
          <p>
            A bounded demonstration of how scope, verdicts, evidence, findings, retest status, and
            integrity limits can be presented in a written report.
          </p>
          <div className="synthetic-banner" role="note">
            <strong>SYNTHETIC SAMPLE / DEMONSTRATION ONLY</strong>
            No client. No real assessment. No target contacted and no requests sent. Every endpoint,
            check, request, response, and finding below is illustrative, not real evidence.
          </div>
          <dl className="sample-meta">
            <div><dt>Client</dt><dd>None — synthetic demonstration</dd></div>
            <div><dt>Target</dt><dd>mcp.example.invalid</dd></div>
            <div><dt>Assessment ID</dt><dd>SYNTHETIC-SAMPLE</dd></div>
            <div><dt>Document status</dt><dd>Demonstration only · not issued</dd></div>
            <div><dt>Authorization</dt><dd>Not obtained or needed here</dd></div>
            <div><dt>Retest</dt><dd>Not performed</dd></div>
          </dl>
        </section>

        <section className="sample-section" aria-labelledby="sample-authorization">
          <h2 id="sample-authorization">1. Authorization</h2>
          <p className="sample-copy">
            No written authorization was obtained or needed for this demonstration because no target
            was contacted and no requests were sent. This is not a representation of client
            authorization. Every real engagement requires written permission and an agreed scope
            before testing begins.
          </p>
        </section>

        <section className="sample-section" aria-labelledby="sample-scope">
          <h2 id="sample-scope">2. Scope</h2>
          <div className="sample-scope">
            <div>
              <h3>Illustrative scope only</h3>
              <p><code>https://mcp.example.invalid</code> is a reserved example domain. The four checks shown below are fabricated to demonstrate report structure; none ran against a server.</p>
            </div>
            <div>
              <h3>Not covered</h3>
              <ul>
                <li>No live endpoint, client, source, or deployment was assessed.</li>
                <li>No token was issued; no state-changing request was executed.</li>
                <li>These four illustrations are not scanner coverage or a complete test set.</li>
              </ul>
            </div>
          </div>
        </section>

        <section className="sample-section" aria-labelledby="sample-summary">
          <h2 id="sample-summary">3. Summary</h2>
          <p className="sample-copy">
            This demonstration contains one illustrative PASS, one illustrative FAIL, one
            illustrative NOT_OBSERVED, and one illustrative EXCLUDED check. These labels explain
            report semantics only; they do not describe an actual server. The sample finding is
            bounded to a missing cache-control directive on a synthetic successful OAuth token
            response.
          </p>
          <div className="sample-callout">
            <strong>Read as a format example, not a result.</strong> No real scan artifact, client
            report, evidence digest, or coverage claim is being published here.
          </div>
        </section>

        <section className="sample-section" aria-labelledby="sample-method">
          <h2 id="sample-method">4. Method and verdicts</h2>
          <p className="sample-copy">
            In a real assessment, each check has a prerequisite and agreed scope. PASS means the
            observed response demonstrated the property; FAIL means it demonstrated an absent or
            misconfigured property; NOT_OBSERVED is inconclusive, not a pass; EXCLUDED means a named
            prerequisite was unmet and the check was not sent. NOT_IMPLEMENTED may be reported where
            a check has not been built and no request is sent. Evidence is redacted. This example
            executed no requests at all.
          </p>
        </section>

        <section className="sample-section" aria-labelledby="sample-coverage">
          <h2 id="sample-coverage">5. Coverage</h2>
          <div className="sample-checks">
            <article className="sample-check">
              <div className="sample-check-heading">
                <span className="sample-status">PASS · illustrative</span>
                <h3>Explicit client authentication</h3>
                <p>POST /oauth/token · synthetic example only</p>
              </div>
              <div className="sample-check-body">
                <p>A fabricated 401 response with <code>invalid_client</code> illustrates evidence that a token request without acceptable client authentication is rejected. No request was made.</p>
                <div className="sample-code">
                  <h4>Synthetic request — no client authentication header</h4>
                  <pre>{`POST /oauth/token HTTP/1.1
Host: mcp.example.invalid
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=sample-client`}</pre>
                </div>
                <div className="sample-code">
                  <h4>Synthetic response</h4>
                  <pre>{`HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Basic realm="token"

{"error":"invalid_client"}`}</pre>
                </div>
              </div>
            </article>

            <article className="sample-check">
              <div className="sample-check-heading">
                <span className="sample-status fail">FAIL · illustrative</span>
                <h3>Token response cache directive</h3>
                <p>POST /oauth/token · synthetic example only</p>
              </div>
              <div className="sample-check-body">
                <p>
                  The fabricated successful OAuth token response below omits
                  <code> Cache-Control: no-store</code>. The absence is the bounded example finding;
                  it is not a CORS result and is not a claim that any cache stored a token.
                </p>
                <div className="sample-code">
                  <h4>Synthetic request — not sent</h4>
                  <pre>{`POST /oauth/token HTTP/1.1
Host: mcp.example.invalid
Content-Type: application/x-www-form-urlencoded
Authorization: Basic [SYNTHETIC REDACTED CREDENTIAL]

grant_type=client_credentials&client_id=sample-client`}</pre>
                </div>
                <div className="sample-code">
                  <h4>Synthetic response — no real token</h4>
                  <pre>{`HTTP/1.1 200 OK
Content-Type: application/json

{"access_token":"[SYNTHETIC PLACEHOLDER — NOT A TOKEN]","token_type":"Bearer","expires_in":300}`}</pre>
                </div>
              </div>
            </article>

            <article className="sample-check">
              <div className="sample-check-heading">
                <span className="sample-status not-observed">NOT_OBSERVED · illustrative</span>
                <h3>JWKS availability</h3>
                <p>GET /auth/jwks · synthetic example only</p>
              </div>
              <div className="sample-check-body">
                <p>A fabricated 503 does not demonstrate the JWKS property either way. NOT_OBSERVED is not a pass; a genuine report would state the specific limitation and evidence.</p>
                <div className="sample-code">
                  <h4>Synthetic response</h4>
                  <pre>{`HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{"error":"temporarily_unavailable"}`}</pre>
                </div>
              </div>
            </article>

            <article className="sample-check">
              <div className="sample-check-heading">
                <span className="sample-status excluded">EXCLUDED · illustrative</span>
                <h3>PKCE S256</h3>
                <p>Authorization flow · synthetic example only</p>
              </div>
              <div className="sample-check-body">
                <p>Excluded because no authorized test client was available for this illustrative scenario. The prerequisite is named; no authorization request was sent.</p>
              </div>
            </article>
          </div>
          <div className="sample-callout">
            The four examples above only demonstrate how report entries may read. They are not a
            list of the scanner's checks, an assertion of scanner coverage, or a promise that these
            checks will be in scope for an engagement.
          </div>
        </section>

        <section className="sample-section" aria-labelledby="sample-findings">
          <h2 id="sample-findings">6. Findings</h2>
          <article className="sample-finding">
            <h4>Illustrative finding: Successful token response lacks Cache-Control: no-store</h4>
            <dl>
              <div><dt>Severity</dt><dd>Medium (illustrative only; no real finding)</dd></div>
              <div><dt>Endpoint</dt><dd><code>POST /oauth/token</code> on <code>mcp.example.invalid</code> (reserved synthetic target).</dd></div>
              <div><dt>Observed</dt><dd>The fabricated successful OAuth token response in section 5 does not include the <code>Cache-Control: no-store</code> directive.</dd></div>
              <div><dt>Evidence</dt><dd>See the clearly marked synthetic request and response above. Neither was sent or received from a real server; the access-token field is a non-token placeholder.</dd></div>
              <div><dt>Why it matters</dt><dd>Without the directive, a cache may retain a token response depending on the client, intermediary, and cache behavior. This synthetic example demonstrates only the missing response directive; it does not show that a token was cached, exposed, or misused.</dd></div>
              <div><dt>Remediation</dt><dd>Return <code>Cache-Control: no-store</code> on successful token responses, and review token endpoint response handling for the agreed scope.</dd></div>
              <div><dt>Retest criteria</dt><dd>After remediation, an authorized retest observes the agreed successful token response and confirms it carries <code>Cache-Control: no-store</code>. No retest has been performed for this sample.</dd></div>
            </dl>
          </article>
        </section>

        <section className="sample-section" aria-labelledby="sample-retest">
          <h2 id="sample-retest">7. Retest</h2>
          <p className="sample-copy">
            Not performed. This is a synthetic demonstration, not a remediation engagement. An
            expanded assessment includes one retest after remediation, within separately agreed
            criteria and scope.
          </p>
        </section>

        <section className="sample-section" aria-labelledby="sample-integrity">
          <h2 id="sample-integrity">8. Integrity</h2>
          <p className="sample-copy">
            No digest is displayed because there is no real scan artifact or downloadable report
            payload behind this example. A genuine assessment report explains the exact content
            covered by any hash and how to reproduce it. A hash may support content consistency
            checks; it does not establish report authorship, evidence authenticity, or that testing
            occurred.
          </p>
        </section>

        <section className="sample-section" aria-labelledby="sample-signature">
          <h2 id="sample-signature">9. Signature and limitations</h2>
          <p className="sample-copy">
            Not issued and not signed as an assessment report. An actual review is limited to the
            written scope and observed behavior; it cannot establish full coverage or guarantee
            safety. This page makes no client, certification, or research-coverage claim.
          </p>
        </section>

        <section className="sample-section">
          <div className="contact-panel">
            <div>
              <span className="eyebrow">Discuss a real, authorized scope</span>
              <h2>Request an Assessment</h2>
              <p>Start with your organization, target description, authorizing party, and desired scope. Do not email secrets.</p>
              <a className="contact-mail" href={assessmentMailto}>lhmisme2011@gmail.com</a>
            </div>
            <div className="contact-actions">
              <Link className="button" href="/request-assessment">Request an Assessment</Link>
              <small>Discuss scope through the inquiry page, or use the email link as a fallback. An inquiry does not authorize testing.</small>
            </div>
          </div>
        </section>
      </div>
    </PublicSiteLayout>
  );
}
