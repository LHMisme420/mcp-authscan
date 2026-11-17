import PublicSiteLayout from './PublicSiteLayout';
import WrittenScopeForm from './WrittenScopeForm';
import './commercial.css';

export default function Scope() {
  return (
    <PublicSiteLayout className="landing">
      <section className="wrap landing-section" aria-labelledby="scope-title">
        <div className="section-head">
          <div>
            <span className="eyebrow">Written authorization first</span>
            <h1 id="scope-title">Start a scope request</h1>
          </div>
          <p>Send the server URL and who authorizes the test. Scope and written authorization are agreed by email before anything is tested. Do not include credentials, tokens or secrets in email.</p>
        </div>
        <div className="written-scope-form-wrap">
          <WrittenScopeForm />
        </div>
      </section>
    </PublicSiteLayout>
  );
}
