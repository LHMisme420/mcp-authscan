export const MAX_REPORT_BYTES = 1024 * 1024;
export const REQUEST_TIMEOUT_MS = 15_000;
const AUTHENTICITY_VERDICTS = [
  'SIGNED BY', 'NOT SIGNED', 'SIGNATURE INVALID', 'UNKNOWN KEY', 'KEY NOT VALID', 'DIVERGENCE',
  'UNSUPPORTED FORM', 'UNREADABLE', 'UNAVAILABLE',
] as const;
export type VerifyResult = {
  integrity: {
    verdict: 'INTACT' | 'ALTERED' | 'UNREADABLE';
    reason: string;
    algorithm: string | null;
    probe_set_version: string | null;
  };
  authenticity: {
    verdict: typeof AUTHENTICITY_VERDICTS[number];
    key_id: string | null;
    reason: string;
  };
  probe_statuses?: { verdict: 'VERIFIED' | 'NOT VERIFIED'; reason: string };
  catalog?: { sha256: string; attestation: string | null };
};

function isVerifyResult(value: unknown): value is VerifyResult {
  if (!value || typeof value !== 'object') return false;
  const response = value as VerifyResult;
  const result = response.integrity;
  const authenticity = response.authenticity;
  return (
    !!result && !!authenticity &&
    (result.verdict === 'INTACT' || result.verdict === 'ALTERED' || result.verdict === 'UNREADABLE') &&
    typeof result.reason === 'string' &&
    (typeof result.algorithm === 'string' || result.algorithm === null) &&
    (typeof result.probe_set_version === 'string' || result.probe_set_version === null) &&
    (AUTHENTICITY_VERDICTS as readonly string[]).includes(authenticity.verdict) &&
    typeof authenticity.reason === 'string' &&
    (typeof authenticity.key_id === 'string' || authenticity.key_id === null) &&
    (response.probe_statuses === undefined ||
      ((response.probe_statuses.verdict === 'VERIFIED' || response.probe_statuses.verdict === 'NOT VERIFIED') &&
        typeof response.probe_statuses.reason === 'string')) &&
    (response.catalog === undefined ||
      (typeof response.catalog.sha256 === 'string' &&
        (typeof response.catalog.attestation === 'string' || response.catalog.attestation === null)))
  );
}

/** Both upload slots use the original single-report endpoint, bytes and response checks. */
export async function verifyReportRequest(text: string, signal: AbortSignal): Promise<VerifyResult> {
  const response = await fetch('/api/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: text, signal,
  });
  if (!response.ok) throw new Error(`The verifier returned HTTP ${response.status}. Please try again.`);
  let payload: unknown;
  try { payload = await response.json(); } catch {
    throw new Error('The verifier returned a response that could not be read.');
  }
  if (!isVerifyResult(payload)) throw new Error('The verifier returned an unexpected response. Please try again.');
  return payload;
}
