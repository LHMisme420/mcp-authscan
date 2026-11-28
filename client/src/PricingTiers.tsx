import { useState, type ReactNode } from 'react';
import WrittenScopeForm from './WrittenScopeForm';

const tiers = [
  {
    name: 'Single-server assessment',
    price: '1750 dollars',
    body: 'One MCP server. Written scope and authorization before testing, evidence-backed findings, and a written report signed by the named researcher. No retest; the full assessment includes one.',
    className: '',
    checkout: 'https://buy.stripe.com/8x2bJ18pI9tP9Dq64E7Vm01',
    buyLabel: 'Pay for the single-server assessment — $1,750',
  },
  {
    name: 'Full assessment',
    price: '3500 dollars',
    body: 'A server or fleet, one written report, one retest, and the written scope agreed by email before testing.',
    className: 'pricing-tier-expanded',
    checkout: 'https://buy.stripe.com/dRmfZh35o6hDcPCakU7Vm02',
    buyLabel: 'Pay for the full assessment — $3,500',
  },
];

export default function PricingTiers(props: {
  emailHref: string;
  homepageVariant?: boolean;
  renderLead?: (openForm: () => void) => ReactNode;
  afterCards?: ReactNode;
  /** Show the scope form on arrival with the Stripe checkout links beneath it (/assessments only). */
  checkout?: boolean;
}) {
  const { homepageVariant = false, renderLead, afterCards, checkout = false } = props;
  const [formOpen, setFormOpen] = useState(checkout);
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
            {!checkout && (tier.name === 'Full assessment' || (homepageVariant && tier.name === 'Single-server assessment')) && (
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
      {checkout && (
        <section className="assessment-checkout" aria-labelledby="assessment-checkout-title">
          <h3 id="assessment-checkout-title">Pay after the form names your server</h3>
          <p>
            Paying reserves the assessment; it does not start a test. After payment, Leroy replies by email to agree
            the written scope and authorization for the server named in the form. Nothing is tested until both are
            agreed in writing.
          </p>
          <div className="hero-ctas assessment-checkout-links">
            {tiers.map((tier, index) => (
              <a
                className={index === 0 ? 'button' : 'button secondary'}
                href={tier.checkout}
                target="_blank"
                rel="noopener noreferrer"
                key={tier.name}
              >
                {tier.buyLabel}
              </a>
            ))}
          </div>
        </section>
      )}
    </section>
    </>
  );
}
