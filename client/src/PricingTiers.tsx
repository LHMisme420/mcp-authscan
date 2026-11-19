import { useState, type ReactNode } from 'react';
import WrittenScopeForm from './WrittenScopeForm';

const tiers = [
  {
    name: 'Single-server assessment',
    price: '1750 dollars',
    body: 'One MCP server or a small set of endpoints. Written scope and authorization before testing, evidence-backed findings, a written report signed by the named researcher, and one retest of the same endpoint after fixes.',
    className: '',
    checkout: 'https://buy.stripe.com/8x2bJ18pI9tP9Dq64E7Vm01',
    buyLabel: 'Buy the single-server assessment',
  },
  {
    name: 'Full assessment',
    price: '3500 dollars',
    body: 'A server or fleet, one written report, one retest, and the written scope agreed by email before testing.',
    className: 'pricing-tier-expanded',
    checkout: 'https://buy.stripe.com/dRmfZh35o6hDcPCakU7Vm02',
    buyLabel: 'Buy the full assessment',
  },
];

export default function PricingTiers(props: {
  emailHref: string;
  homepageVariant?: boolean;
  renderLead?: (openForm: () => void) => ReactNode;
  afterCards?: ReactNode;
}) {
  const { homepageVariant = false, renderLead, afterCards } = props;
  const [formOpen, setFormOpen] = useState(false);
  const openForm = () => setFormOpen(true);

  return (
    <>
    {renderLead?.(openForm)}
    <section className="pricing-tiers" aria-labelledby="pricing-tiers-title">
      <h2 id="pricing-tiers-title">Independent MCP security assessments</h2>
      <div className="pricing-tier-grid">
        {tiers.map((tier, index) => (
          <article className={`pricing-tier ${tier.className}`} key={tier.name}>
            <span className="pricing-tier-index">0{index + 1}</span>
            <h3>{tier.name}</h3>
            <strong className="pricing-tier-price">{tier.price}</strong>
            <p>{tier.body}</p>
            {(tier.name === 'Full assessment' || (homepageVariant && tier.name === 'Single-server assessment')) && (
              <button className="button pricing-start-button" type="button" onClick={() => setFormOpen((open) => !open)}>
                {formOpen ? 'Close assessment form' : 'Start an assessment'}
              </button>
            )}
          </article>
        ))}
      </div>
      {afterCards}
      {formOpen && (
        <div className="written-scope-form-wrap">
          <WrittenScopeForm />
        </div>
      )}
    </section>
    </>
  );
}
