import { displayGradeValue, type GradeComparison } from './compareReportGrades';
import type { VerifyResult } from './verifyReportRequest';

export default function ReportGradeComparison({ comparison, first, second, names }: {
  comparison: GradeComparison; first: VerifyResult | null; second: VerifyResult | null; names: [string, string];
}) {
  return <section className="verify-result verify-comparison" aria-labelledby="verify-comparison-title" aria-live="polite">
    <span className="eyebrow">Two-file comparison</span>
    <h2 id="verify-comparison-title">{comparison.reason}</h2>
    <p>Comparison of declared graded fields only; it does not replace either file’s integrity or signature verdict.
      Run dates are displayed for identification, not compared or authenticated by this comparison.</p>
    <dl className="verify-result-meta">
      {[first, second].map((result, index) => <div key={index}>
        <dt>File {index === 0 ? 'one' : 'two'} — {names[index]}</dt>
        <dd>Run date: {comparison.runDates?.[index] ?? 'Not declared'}</dd>
        <dd>Hash scheme: {comparison.schemes?.[index] ?? 'Not declared'}</dd>
        <dd>Signing key: {result ? `${result.authenticity.verdict}${result.authenticity.key_id ? ` ${result.authenticity.key_id}` : ''}` : 'Verification unavailable'}</dd>
      </div>)}
    </dl>
    {comparison.probes.length > 0 && <div className="verify-comparison-scroll">
      <table className="verify-comparison-table">
        <caption>Differing probe rows</caption>
        <thead><tr><th>Probe id</th><th>File one — probe name</th><th>File one — status</th>
          <th>File two — probe name</th><th>File two — status</th></tr></thead>
        <tbody>{comparison.probes.map(row => <tr key={JSON.stringify(row.probeId)}>
          <td>{row.probeId}</td><td>{row.first?.name ?? 'Missing row'}</td><td>{row.first?.status ?? 'Missing row'}</td>
          <td>{row.second?.name ?? 'Missing row'}</td><td>{row.second?.status ?? 'Missing row'}</td>
        </tr>)}</tbody>
      </table>
    </div>}
    {comparison.totals.length > 0 && <ul>{comparison.totals.map(total =>
      <li key={total.name}><strong>{total.name}</strong>: file one {displayGradeValue(total.first)}; file two {displayGradeValue(total.second)}</li>
    )}</ul>}
    {comparison.outcome === 'different-schemes' && !comparison.probes.length && !comparison.totals.length &&
      <p>No differences in the requested probe names/statuses or totals. The different hash schemes prevent an identical classification.</p>}
    <p>Ignored: headers, body excerpts, endpoints, elapsed time and timestamps. Those differences are not findings.</p>
  </section>;
}
