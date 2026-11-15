import PublicSiteLayout from "./PublicSiteLayout";

export default function BlastRadius() {
  return (
    <PublicSiteLayout className="sample-page">
      <div className="wrap">
        <section className="sample-header">
          <h1>MCP AuthScan Blast Radius</h1>
          <p>This page describes what an MCP AuthScan assessment report contains.</p>
          <p>You know what your AI agents are supposed to access. We prove what they actually can.</p>
        </section>

        <section className="sample-section">
          <h2>VERIFIED ACCESS</h2>
          <p className="sample-copy">
            What the deployment proved it can reach, with the identity it was given. Every line here came from a request carrying a customer-issued credential, under written permission for that specific action, and a response that demonstrated the capability. Nothing in this section is inferred.
          </p>
        </section>

        <section className="sample-section">
          <h2>POTENTIAL ACCESS</h2>
          <p className="sample-copy">
            What was readable without a credential, or declared by the deployment itself. Each line names the single prerequisite that would promote it to verified, so you can argue about the prerequisite instead of the finding.
          </p>
        </section>

        <section className="sample-section">
          <h2>UNKNOWN ACCESS</h2>
          <p className="sample-copy">
            What the assessment could not reach, named with the reason. This section is never blank. A list of unknowns is information. An empty list is a false claim.
          </p>
        </section>

        <section className="sample-section">
          <p className="sample-copy">
            Every report carries a hash over its graded content: probe results, findings, severities, and the basis for each severity. Timestamps, elapsed time and server-varying headers are excluded, so the same scan of the same target computes the same hash. A second party re-runs the same probe set against the same target. MATCH means the graded content is identical. DIVERGENCE names the fields that differ rather than asserting the tool was wrong. NOT_REPRODUCIBLE means the hash could not be recomputed at all.
          </p>
        </section>

        <section className="sample-section">
          <p className="sample-copy">
            The claim is not that the tool is right. The claim is that it can be caught. What we tested, and what we did not, is stated on every report, against a named probe-set version.
          </p>
        </section>
      </div>
    </PublicSiteLayout>
  );
}
