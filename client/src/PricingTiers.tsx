const tiers = [
  {
    name: 'Single-server assessment',
    price: '1750 dollars',
    body: 'One MCP server or a small set of endpoints. Written scope and authorization before testing, evidence-backed findings, a written report signed by the named researcher, and one retest of the same endpoint after fixes.',
    className: '',
  },
  {
    name: 'Expanded assessment',
    price: '3500 dollars',
    body: 'A server or a fleet, broader agreed scope. Written scope and authorization before testing, evidence-backed findings, a written report signed by the named researcher, and one defined remediation retest.',
    className: 'pricing-tier-expanded',
  },
  {
    name: 'Single-server assessment with publication',
    price: '2500 dollars',
    body: 'The same scope as the 1750 assessment. The lower price is in exchange for permission to publish a redacted result after your fix window closes, naming no credentials, no tokens and no internal detail. You review the redacted text before it goes out.',
    className: '',
  },
];

export default function PricingTiers({ emailHref }: { emailHref: string }) {
  return (
    <section className="pricing-tiers" aria-labelledby="pricing-tiers-title">
      <h2 id="pricing-tiers-title">Independent MCP security assessments</h2>
      <div className="pricing-tier-grid">
        {tiers.map((tier, index) => (
          <article className={`pricing-tier ${tier.className}`} key={tier.name}>
            <span className="pricing-tier-index">0{index + 1}</span>
            <h3>{tier.name}</h3>
            <strong className="pricing-tier-price">{tier.price}</strong>
            <p>{tier.body}</p>
            <a className="text-link" href={emailHref}>Email us to request an assessment</a>
          </article>
        ))}
      </div>
      <p className="pricing-tier-terms">
        Scope, deliverables and the publication option are agreed in writing before testing. No mandatory call is part of any assessment.
      </p>
    </section>
  );
}
