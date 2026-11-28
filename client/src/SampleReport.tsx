import PublicSiteLayout from './PublicSiteLayout';

// Owner-frozen wording: do not edit for tone. Any copy change requires the
// owner's review and an explicit update to the approved-copy regression fixture.
// 2026-11-19: owner-requested change. The AgentPayStore run is labelled a development
// build (its probe set 2026.11.16.2 is in no release) and a reproducible 1.1.26 sample
// sits beside it in its own article, outside the approved-copy fixture.
const RH_SHORT = '5f6dc1c9';
const FIXTURE = `import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
class H(BaseHTTPRequestHandler):
    def _s(self, o, c=200):
        b = b"" if o is None else json.dumps(o).encode()
        self.send_response(c); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        m = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        meth, i = m.get("method"), m.get("id")
        if meth == "initialize":
            self._s({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                     "serverInfo": {"name": "fx", "version": "0"}, "instructions": "x" * 900}})
        elif meth == "tools/list":
            self._s({"jsonrpc": "2.0", "id": i, "result": {"tools": [{"name": "list_docs", "description": "d", "inputSchema": {"type": "object"}}]}})
        elif meth in ("prompts/list", "resources/list"):
            self._s({"jsonrpc": "2.0", "id": i, "result": {meth.split("/")[0]: []}})
        elif i is None: self._s(None, 202)
        else: self._s({"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "nf"}})
    def do_GET(self): self._s({"error": "nf"}, 404)
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
`;
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
          <p>Scanner: a development build of mcp-authscan that reported itself as 1.1.24, probe set 2026.11.16.2, severity calibration 2026.11.07.1</p>
          <p>Development build, not a release: no published version of mcp-authscan ships probe set 2026.11.16.2 (the published 1.1.24 ships 2026.11.10.1), so this run cannot be repeated from PyPI. The write-up and its hash are kept exactly as recorded. To run the checks yourself, use the reproducible sample below.</p>
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
            This server has not been retested. The full assessment includes one retest of the same endpoint after fixes, and the two hashes side by side are the before and after.
          </p>
          <div className="hero-ctas">
            <a className="button" href="https://buy.stripe.com/8x2bJ18pI9tP9Dq64E7Vm01">Single-server assessment — $1,750</a>{' '}
            <a className="button secondary" href="https://buy.stripe.com/dRmfZh35o6hDcPCakU7Vm02">Full assessment — $3,500</a>
          </div>
        </article>
        <article id="reproducible-sample" className="sample-section" style={{ overflowWrap: 'anywhere' }}>
          <h2>REPRODUCIBLE SAMPLE: RUN IT YOURSELF</h2>
          <p>
            Everything below uses a published release and a published probe set, so you can repeat it and compare
            your result with the one shown. The target is a small test server you run on your own machine.
          </p>
          <p>Scanner: mcp-authscan 1.1.52, probe set 2026.11.28.3, severity calibration 2026.11.07.1.</p>
          <p>Wheel sha256: f961017b13073f9705f579832ce59144cc836d7c9f039f6ee28a7bffe437d339</p>
          <h2>STEPS</h2>
          <p>1. Install the release and check you received the published wheel:</p>
          <pre><code>{`python3 -m venv v
v/bin/pip install "mcp-authscan[signing]==1.1.52"
v/bin/pip download --no-deps mcp-authscan==1.1.52 -d wheel
sha256sum wheel/mcp_authscan-1.1.52-py3-none-any.whl`}</code></pre>
          <p>2. Save this test server as fixture.py and start it. It answers MCP with no authentication and lists one tool:</p>
          <pre><code>{FIXTURE}</code></pre>
          <pre><code>{`python3 fixture.py 19191 &`}</code></pre>
          <p>3. Scan it. The names you give are recorded in the report but are not part of the hash:</p>
          <pre><code>{`v/bin/mcp-authscan http://127.0.0.1:19191/mcp --json --output report.json \\
  --authorized-by "Your Name" --auth-basis "my own local test server" \\
  --contact "you@example.com" --allow-private`}</code></pre>
          <h2>WHAT YOU SHOULD SEE</h2>
          <p>Exit code 1: one finding, HIGH, ZERO-AUTH, Unauthenticated MCP endpoint. Coverage 1.0.</p>
          <p>Report hash: f679fc77bc27f73836c147cefe7efa8fcf3f0e763c1292f179fdf40c244d2028</p>
          <p>Security state ID (anonymous): 5699f598ef6b9664b4c5d908b457484e5108fcd19a2688e0ef68b1b7c4df0c73</p>
          <p>4. Verify it, and map it to the release that produced it:</p>
          <pre><code>{`v/bin/python -m mcp_authscan.report_verify report.json
v/bin/python -m mcp_authscan.releases report.json`}</code></pre>
          <p>
            The first prints MATCH and UNSIGNED with the report hash above. The second lists release 1.1.52 for probe
            set 2026.11.28.3 and installed_matches true. A different hash means different graded content: a
            different release, probe set, server or URL. The port is part of the URL.
          </p>
          <p>
            MATCH proves integrity only: anyone who can edit the file can recompute a hash. Who made a report is
            what the signature answers, so sign this scan with a key of your own and check it.
          </p>
          <p>5. Make your own signing key, write its public half as a keys file, then scan again with --sign (the scan comes last because it exits 1 on the finding):</p>
          <pre><code>{`v/bin/python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K; from cryptography.hazmat.primitives import serialization as s; open('key.pem','wb').write(K.generate().private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption()))"
v/bin/python -c "import base64, hashlib, json; from cryptography.hazmat.primitives import serialization as s; k = s.load_pem_private_key(open('key.pem','rb').read(), None).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw); json.dump([{'key_id': hashlib.sha256(k).hexdigest(), 'alg': 'ed25519', 'public_key': base64.urlsafe_b64encode(k).rstrip(b'=').decode()}], open('keys.json', 'w'))"
MCP_AUTHSCAN_SIGNING_KEY=key.pem MCP_AUTHSCAN_LEDGER_DIR=./ledger v/bin/mcp-authscan http://127.0.0.1:19191/mcp --json --sign --output signed.json \\
  --authorized-by "Your Name" --auth-basis "my own local test server" --contact "you@example.com" --allow-private`}</code></pre>
          <p>6. Verify the signed report against your own keys file:</p>
          <pre><code>{`v/bin/python -m mcp_authscan.report_verify --keys keys.json signed.json`}</code></pre>
          <p>
            It prints MATCH and SIGNED BY followed by your key id, the SHA-256 of your public key. The report hash is
            the same {RH_SHORT} as above, because signing does not change the graded content. Edit any graded
            field in signed.json and the same command prints MISMATCH and SIGNATURE INVALID, and exits 1. The private key never leaves your
            machine; only keys.json is shared with whoever checks your reports.
          </p>
        </article>
      </div>
    </PublicSiteLayout>
  );
}
