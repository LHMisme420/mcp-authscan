import type { VerifyResult } from './verifyReportRequest';

export default function VerifyResultPanels({ result, second = false }: { result: VerifyResult; second?: boolean }) {
  const prefix = second ? 'verify-second' : 'verify';
  const resultLabel = result.integrity.verdict === 'INTACT' ? 'Digest matches'
    : result.integrity.verdict === 'ALTERED' ? 'Digest does not match' : 'Could not verify';
  return <>
    <section className={`verify-result verify-result-${result.integrity.verdict.toLowerCase()}`}
      aria-labelledby={`${prefix}-result-title`} aria-live="polite">
      <div className="verify-result-heading">
        <span className="eyebrow">{second ? 'File two — Integrity' : 'Integrity'}</span>
        <span className={`verify-verdict verify-verdict-${result.integrity.verdict.toLowerCase()}`}>{result.integrity.verdict}</span>
      </div>
      <h2 id={`${prefix}-result-title`}>{resultLabel}</h2>
      <p className="verify-result-reason">{result.integrity.reason}</p>
      <dl className="verify-result-meta">
        <div><dt>Algorithm</dt><dd>{result.integrity.algorithm ?? 'Not declared'}</dd></div>
        <div><dt>Declared probe set</dt><dd>{result.integrity.probe_set_version ?? 'Not declared'}</dd></div>
        {result.catalog && <div><dt>Probe-set catalog</dt>
          <dd>{result.catalog.attestation ?? 'Not evaluated'} (catalog sha256 {result.catalog.sha256.slice(0, 12)}…)</dd></div>}
      </dl>
    </section>
    <section className="verify-result" aria-labelledby={`${prefix}-authenticity-title`} aria-live="polite">
      <div className="verify-result-heading">
        <span className="eyebrow">{second ? 'File two — Authenticity' : 'Authenticity'}</span>
        <span className="verify-verdict">
          {result.authenticity.verdict}{result.authenticity.verdict === 'SIGNED BY' ? ` ${result.authenticity.key_id}` : ''}
        </span>
      </div>
      <h2 id={`${prefix}-authenticity-title`}>Signature verification</h2>
      <p className="verify-result-reason">{result.authenticity.reason}</p>
      <dl className="verify-result-meta">
        <div><dt>Claimed key_id</dt><dd>{result.authenticity.key_id ?? 'Not declared'}</dd></div>
        {result.probe_statuses && <div><dt>Probe statuses</dt>
          <dd>{result.probe_statuses.verdict}: {result.probe_statuses.reason}</dd></div>}
        <div><dt>Published keys</dt><dd><a href="/keys.json">/keys.json</a></dd></div>
      </dl>
    </section>
  </>;
}
