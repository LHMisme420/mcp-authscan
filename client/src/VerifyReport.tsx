import { useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import PublicSiteLayout from './PublicSiteLayout';
import './commercial.css';
import './VerifyReport.css';

const MAX_REPORT_BYTES = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;

type VerifyResult = {
  verdict: 'INTACT' | 'ALTERED' | 'UNREADABLE';
  reason: string;
  algorithm: string | null;
  probe_set_version: string | null;
};

function isVerifyResult(value: unknown): value is VerifyResult {
  if (!value || typeof value !== 'object') return false;
  const result = value as Record<string, unknown>;
  return (
    (result.verdict === 'INTACT' || result.verdict === 'ALTERED' || result.verdict === 'UNREADABLE') &&
    typeof result.reason === 'string' &&
    (typeof result.algorithm === 'string' || result.algorithm === null) &&
    (typeof result.probe_set_version === 'string' || result.probe_set_version === null)
  );
}

function byteLength(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

export default function VerifyReport() {
  const [reportText, setReportText] = useState('');
  const [fileName, setFileName] = useState('');
  const [inputError, setInputError] = useState('');
  const [requestError, setRequestError] = useState('');
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [pending, setPending] = useState(false);
  const requestIdRef = useRef(0);
  const activeRequestRef = useRef<AbortController | null>(null);

  function clearPreviousCheck() {
    requestIdRef.current += 1;
    activeRequestRef.current?.abort();
    activeRequestRef.current = null;
    setPending(false);
    setResult(null);
    setRequestError('');
    setInputError('');
  }

  function handleTextChange(event: ChangeEvent<HTMLTextAreaElement>) {
    const nextText = event.currentTarget.value;
    clearPreviousCheck();
    setReportText(nextText);
    setFileName('');
    if (byteLength(nextText) > MAX_REPORT_BYTES) {
      setInputError('This JSON is larger than the 1 MiB limit. Shorten it before checking.');
    }
  }

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    clearPreviousCheck();
    const readId = requestIdRef.current;
    setFileName(file.name);
    if (file.size > MAX_REPORT_BYTES) {
      setReportText('');
      setInputError('That file is larger than the 1 MiB limit. Choose a smaller JSON file.');
      event.currentTarget.value = '';
      return;
    }
    try {
      const contents = await file.text();
      if (readId !== requestIdRef.current) return;
      setReportText(contents);
      if (byteLength(contents) > MAX_REPORT_BYTES) {
        setInputError('This JSON is larger than the 1 MiB limit. Choose a smaller file.');
      }
    } catch {
      if (readId !== requestIdRef.current) return;
      setReportText('');
      setFileName('');
      setInputError('The selected file could not be read. Choose another JSON file.');
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearPreviousCheck();

    if (!reportText.trim()) {
      setInputError('Paste a JSON report or choose a JSON file to continue.');
      return;
    }
    if (byteLength(reportText) > MAX_REPORT_BYTES) {
      setInputError('This JSON is larger than the 1 MiB limit. Shorten it before checking.');
      return;
    }

    const requestId = requestIdRef.current;
    const controller = new AbortController();
    let timedOut = false;
    activeRequestRef.current = controller;
    setPending(true);
    const timeout = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: reportText,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`The verifier returned HTTP ${response.status}. Please try again.`);
      }

      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        throw new Error('The verifier returned a response that could not be read.');
      }
      if (!isVerifyResult(payload)) {
        throw new Error('The verifier returned an unexpected response. Please try again.');
      }
      if (requestId === requestIdRef.current) setResult(payload);
    } catch (error) {
      if (requestId !== requestIdRef.current) return;
      if (timedOut) {
        setRequestError('The check timed out after 15 seconds. Please try again.');
      } else if (error instanceof Error && error.name === 'AbortError') {
        setRequestError('The check was interrupted. Please try again.');
      } else {
        setRequestError(error instanceof Error ? error.message : 'The report could not be checked. Please try again.');
      }
    } finally {
      window.clearTimeout(timeout);
      if (requestId === requestIdRef.current) {
        activeRequestRef.current = null;
        setPending(false);
      }
    }
  }

  const resultLabel = result?.verdict === 'INTACT'
    ? 'Digest matches'
    : result?.verdict === 'ALTERED'
      ? 'Digest does not match'
      : 'Could not verify';

  return (
    <PublicSiteLayout className="landing">
      <div className="wrap verify-page">
        <header className="verify-heading">
          <span className="eyebrow">A free, local-to-this-service check</span>
          <h1>Verify a report</h1>
          <p>
            Reports in the supported format include a digest over graded content: probe results,
            findings, severities, and the stated reason for each severity. Timestamps and elapsed
            time are excluded.
          </p>
          <p>Paste the JSON or select the file. We recompute the digest and compare it with the stored value.</p>
        </header>

        <section className="verify-workspace" aria-labelledby="verify-form-title">
          <div className="verify-form-intro">
            <span className="eyebrow">Report check</span>
            <h2 id="verify-form-title">Check the report’s stored digest</h2>
            <p>Supported reports use schema 3 and verdict-v3. No account is needed.</p>
          </div>

          <form className="verify-form" onSubmit={handleSubmit} noValidate>
            <label htmlFor="verify-json">Report JSON</label>
            <textarea
              id="verify-json"
              name="report"
              value={reportText}
              onChange={handleTextChange}
              placeholder={'Paste the complete report JSON here…'}
              spellCheck={false}
              aria-describedby="verify-input-help verify-input-error"
            />
            <div className="verify-input-meta">
              <span id="verify-input-help">
                Maximum 1 MiB. The JSON is sent only to this site’s verifier endpoint.
              </span>
              <span>{byteLength(reportText).toLocaleString()} / 1,048,576 bytes</span>
            </div>

            <div className="verify-file-row">
              <label htmlFor="verify-file">Or choose a JSON file</label>
              <input
                id="verify-file"
                type="file"
                accept=".json,application/json"
                onChange={handleFileChange}
                aria-describedby="verify-file-note"
              />
              {fileName && <span className="verify-file-name">{fileName}</span>}
              <span id="verify-file-note" className="verify-file-note">Files over 1 MiB are not read.</span>
            </div>

            {inputError && <p className="verify-message verify-message-error" id="verify-input-error" role="alert">{inputError}</p>}
            {requestError && <p className="verify-message verify-message-error" role="alert">{requestError}</p>}

            <button className="button verify-submit" type="submit" disabled={pending}>
              {pending ? 'Checking report…' : 'Verify report'}
            </button>
            <p className="verify-privacy-note">
              The request contains only the JSON you provide. This page does not scan a target, rerun
              checks, or store the report.
            </p>
          </form>
        </section>

        {pending && (
          <section className="verify-pending" aria-live="polite" aria-label="Verification in progress">
            <div className="verify-skeleton-line" />
            <div className="verify-skeleton-line short" />
          </section>
        )}

        {result && !pending && (
          <section
            className={`verify-result verify-result-${result.verdict.toLowerCase()}`}
            aria-labelledby="verify-result-title"
            aria-live="polite"
          >
            <div className="verify-result-heading">
              <span className="eyebrow">Verification result</span>
              <span className={`verify-verdict verify-verdict-${result.verdict.toLowerCase()}`}>{result.verdict}</span>
            </div>
            <h2 id="verify-result-title">{resultLabel}</h2>
            <p className="verify-result-reason">{result.reason}</p>
            <dl className="verify-result-meta">
              <div>
                <dt>Algorithm</dt>
                <dd>{result.algorithm ?? 'Not declared'}</dd>
              </div>
              <div>
                <dt>Declared probe set</dt>
                <dd>{result.probe_set_version ?? 'Not declared'}</dd>
              </div>
            </dl>
          </section>
        )}

        <section className="verify-limits" aria-labelledby="verify-limits-title">
          <span className="eyebrow">What this check tells you</span>
          <h2 id="verify-limits-title">A digest comparison, not a provenance claim.</h2>
          <p>
            An <strong>INTACT</strong> result means the graded content matches the digest currently
            stored in the report. It does not prove who produced the report or that it was never
            edited: someone who changes the content can also recompute and replace an unkeyed hash.
          </p>
          <p>
            <strong>ALTERED</strong> means the content does not match its stored digest.
            <strong> UNREADABLE</strong> means this verifier could not evaluate the report, with the
            reason shown above. This check does not establish that a server was secure or that a scan
            was authorized; review the report’s scope and authorization separately.
          </p>
          <div className="verify-support-note">
            <strong>Supported format</strong>
            <span>Schema-3 reports using verdict-v3 only. This tool does not scan or rerun tests, and it does not retain submitted reports.</span>
          </div>
        </section>
      </div>
    </PublicSiteLayout>
  );
}
