import { useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import PublicSiteLayout from './PublicSiteLayout';
import ReleaseEvidence from './ReleaseEvidence';
import VerifyResultPanels from './VerifyResultPanels';
import ReportGradeComparison from './ReportGradeComparison';
import { compareReportGrades, type GradeComparison } from './compareReportGrades';
import { MAX_REPORT_BYTES, REQUEST_TIMEOUT_MS, verifyReportRequest, type VerifyResult } from './verifyReportRequest';
import './commercial.css';
import './VerifyReport.css';

function byteLength(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

export default function VerifyReport() {
  const [reportText, setReportText] = useState('');
  const [fileName, setFileName] = useState('');
  const [inputError, setInputError] = useState('');
  const [requestError, setRequestError] = useState('');
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [secondText, setSecondText] = useState('');
  const [secondName, setSecondName] = useState('');
  const [secondInputError, setSecondInputError] = useState('');
  const [secondRequestError, setSecondRequestError] = useState('');
  const [secondResult, setSecondResult] = useState<VerifyResult | null>(null);
  const [comparison, setComparison] = useState<GradeComparison | null>(null);
  const [pending, setPending] = useState(false);
  const [readingFiles, setReadingFiles] = useState(0);
  const firstReadId = useRef(0);
  const secondReadId = useRef(0);
  const requestIdRef = useRef(0);
  const activeRequestRef = useRef<AbortController | null>(null);

  function clearPreviousCheck() {
    requestIdRef.current += 1;
    activeRequestRef.current?.abort();
    activeRequestRef.current = null;
    setPending(false);
    setResult(null);
    setSecondResult(null);
    setComparison(null);
    setSecondRequestError('');
    setRequestError('');
    setInputError('');
  }

  function handleTextChange(event: ChangeEvent<HTMLTextAreaElement>) {
    const nextText = event.currentTarget.value;
    clearPreviousCheck();
    firstReadId.current += 1;
    setReportText(nextText);
    setFileName('');
    if (byteLength(nextText) > MAX_REPORT_BYTES) {
      setInputError('This JSON is larger than the 1 MiB limit. Shorten it before checking.');
    }
  }

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>, second = false) {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    clearPreviousCheck();
    const readRef = second ? secondReadId : firstReadId;
    const readId = ++readRef.current;
    const setText = second ? setSecondText : setReportText;
    const setName = second ? setSecondName : setFileName;
    const setError = second ? setSecondInputError : setInputError;
    setError('');
    setText('');
    setName(file.name);
    if (file.size > MAX_REPORT_BYTES) {
      setError('That file is larger than the 1 MiB limit. Choose a smaller JSON file.');
      event.currentTarget.value = '';
      return;
    }
    setReadingFiles(count => count + 1);
    try {
      const contents = await file.text();
      if (readId !== readRef.current) return;
      clearPreviousCheck();
      setText(contents);
      if (byteLength(contents) > MAX_REPORT_BYTES) {
        setError('This JSON is larger than the 1 MiB limit. Choose a smaller file.');
      }
    } catch {
      if (readId !== readRef.current) return;
      setText('');
      setName('');
      setError('The selected file could not be read. Choose another JSON file.');
    } finally {
      setReadingFiles(count => count - 1);
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearPreviousCheck();

    if (readingFiles || secondInputError || (secondName && !secondText.trim())) return;
    if (!reportText.trim()) {
      setInputError('Paste a JSON report or choose a JSON file to continue.');
      return;
    }
    if (byteLength(reportText) > MAX_REPORT_BYTES) {
      setInputError('This JSON is larger than the 1 MiB limit. Shorten it before checking.');
      return;
    }
    if (byteLength(secondText) > MAX_REPORT_BYTES) {
      setSecondInputError('This JSON is larger than the 1 MiB limit. Choose a smaller file.');
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
      const checks = await Promise.allSettled([
        verifyReportRequest(reportText, controller.signal),
        ...(secondText ? [verifyReportRequest(secondText, controller.signal)] : []),
      ]);
      if (requestId !== requestIdRef.current) return;
      const errorMessage = (error: unknown) => timedOut ? 'The check timed out after 15 seconds. Please try again.'
        : error instanceof Error && error.name === 'AbortError' ? 'The check was interrupted. Please try again.'
          : error instanceof Error ? error.message : 'The report could not be checked. Please try again.';
      if (checks[0].status === 'fulfilled') setResult(checks[0].value);
      else setRequestError(errorMessage(checks[0].reason));
      if (checks[1]?.status === 'fulfilled') setSecondResult(checks[1].value);
      else if (checks[1]?.status === 'rejected') setSecondRequestError(errorMessage(checks[1].reason));
      if (secondText) {
        setComparison(checks.every(check => check.status === 'fulfilled')
          ? compareReportGrades(reportText, secondText)
          : { outcome: 'unavailable', reason: 'Comparison unavailable: both files must complete their verification request.',
              probes: [], totals: [] });
      }
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

  return (
    <PublicSiteLayout className="landing">
      <div className="wrap verify-page">
        <header className="verify-heading">
          <span className="eyebrow">A free, local-to-this-service check</span>
          <h1>Verify a report</h1>
          <p>Two questions, answered separately.</p>
          <p><strong>Integrity.</strong> Does this file still match the hash it carries? Intact, altered, or unreadable with the reason printed.</p>
          <p><strong>Authenticity.</strong> Is it signed by the key it claims? Signed by that key, not signed, signature invalid, or unknown key.</p>
        </header>

        <ReleaseEvidence />

        <section className="verify-workspace" aria-labelledby="verify-form-title">
          <div className="verify-form-intro">
            <span className="eyebrow">Report check</span>
            <h2 id="verify-form-title">Check integrity and authenticity</h2>
            <p>Supported reports use schema 3 and verdict-v3 or verdict-v4. No account is needed.</p>
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
                onChange={event => handleFileChange(event)}
                aria-describedby="verify-file-note"
              />
              {fileName && <span className="verify-file-name">{fileName}</span>}
              <span id="verify-file-note" className="verify-file-note">Files over 1 MiB are not read.</span>
            </div>

            <div className="verify-file-row">
              <label htmlFor="verify-second-file">Optional second JSON file to compare</label>
              <input id="verify-second-file" type="file" accept=".json,application/json"
                onChange={event => handleFileChange(event, true)}
                aria-describedby="verify-second-note verify-second-input-error" />
              {secondName && <span className="verify-file-name">{secondName}</span>}
              <span id="verify-second-note" className="verify-file-note">
                Maximum 1 MiB per file. Each file gets its own integrity and signature check.
              </span>
              {(secondName || secondInputError) && <button type="button" onClick={() => {
                clearPreviousCheck();
                secondReadId.current += 1;
                setSecondText(''); setSecondName(''); setSecondInputError('');
                const input = document.getElementById('verify-second-file') as HTMLInputElement | null;
                if (input) input.value = '';
              }}>Remove second file</button>}
            </div>
            {inputError && <p className="verify-message verify-message-error" id="verify-input-error" role="alert">{inputError}</p>}
            {requestError && <p className="verify-message verify-message-error" role="alert">{requestError}</p>}
            {secondInputError && <p className="verify-message verify-message-error" id="verify-second-input-error" role="alert">File two: {secondInputError}</p>}
            {secondRequestError && <p className="verify-message verify-message-error" role="alert">File two: {secondRequestError}</p>}

            <button className="button verify-submit" type="submit" disabled={pending || readingFiles > 0 || !!secondInputError}>
              {pending ? 'Checking report…' : secondText ? 'Verify and compare reports' : 'Verify report'}
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

        {result && !pending && <>
          {comparison && <h2>File one — {fileName || 'Pasted JSON'}</h2>}
          <VerifyResultPanels result={result} />
        </>}
        {secondResult && !pending && <VerifyResultPanels result={secondResult} second />}
        {comparison && !pending && <ReportGradeComparison comparison={comparison} first={result}
          second={secondResult} names={[fileName || 'Pasted JSON', secondName]} />}

        <section className="verify-limits" aria-labelledby="verify-limits-title">
          <span className="eyebrow">What this check tells you</span>
          <h2 id="verify-limits-title">Two independent answers.</h2>
          <p>
            A hash alone can be recomputed by anyone who can edit the file. Integrity means
            the graded content matches the hash it carries, not that nobody edited it.
            A valid signature means the canonical graded content was signed by whoever holds
            the private half of the published key. Both answers apply to graded content,
            not to excluded fields such as timestamps.
          </p>
          <p>
            Under verdict-v3, probe statuses sit outside the hash; verdict-v4 includes graded probe rows.
            Only a verified sig_version 3 or 4 signature authenticates them;
            for every other report, including one with a valid older signature, this page says
            the probe statuses are NOT VERIFIED. Signatures are checked against a pinned key history:
            a key withdrawn from publication rejects every signature, because a report carries no
            signed signing time.
          </p>
          <p>
            Read the scope section of a report to see what was authorized and what was not tested.
            Neither answer proves that the server was secure. A hash cannot tell you which field changed.
            Malformed input is reported as UNREADABLE with a reason.
          </p>
          <div className="verify-support-note">
            <strong>Supported format</strong>
            <span>Schema-3 reports using verdict-v3 or verdict-v4, plus the pre-schema-3 format written by releases 1.1.21 to 1.1.24. That format is checked with its own pre-1.1.25 algorithm and its result is marked LEGACY; it was never signed, so it always shows NOT SIGNED. This site checks Ed25519 signatures; it does not create them or hold private keys. Signing belongs in the CLI on the signer’s machine. Unsigned reports show NOT SIGNED. This tool does not scan or rerun tests, and it does not retain submitted reports.</span>
          </div>
        </section>
      </div>
    </PublicSiteLayout>
  );
}
