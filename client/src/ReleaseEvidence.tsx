
import { useState, type ChangeEvent } from 'react';

const EXPECTED = '11679e0b0ff85b9fef6df4e3d440098aecf5fdf20e5d1c89b79ce6954809fc8a';

export default function ReleaseEvidence() {
  const [message, setMessage] = useState('');
  const [hash, setHash] = useState('');

  async function verify(event: ChangeEvent<HTMLInputElement>) {
    setMessage('');
    setHash('');

    const file = event.currentTarget.files?.[0];
    if (!file) return;

    if (file.size > 1048576) {
      setMessage('ERROR: File exceeds 1 MiB.');
      return;
    }

    try {
      const bytes = await file.arrayBuffer();
      const result = await crypto.subtle.digest('SHA-256', bytes);
      const calculated = Array.from(new Uint8Array(result))
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');

      setHash(calculated);

      setMessage(calculated === EXPECTED
        ? 'MATCH: Identical to the published v1.1.46 receipt.'
        : 'MISMATCH: This file differs from the published receipt.');
    } catch {
      setMessage('ERROR: Unable to check the file.');
    }
  }

  return (
    <section className="verify-workspace"
      aria-labelledby="release-evidence-title">
      <div className="verify-form-intro">
        <span className="eyebrow">Release Evidence</span>
        <h2 id="release-evidence-title">
          Verify MCP AuthScan v1.1.46
        </h2>
        <p>
          Download verification-receipt.json from the{' '}
          <a href="https://github.com/LHMisme420/mcp-authscan/releases/tag/v1.1.46">
            official GitHub Release
          </a>.
          Upload it below to compare its SHA-256.
        </p>
      </div>

      <div className="verify-form">
        <label htmlFor="regression-receipt">
          Upload verification receipt
        </label>
        <input
          id="regression-receipt"
          type="file"
          accept=".json,application/json"
          onChange={verify}
        />

        <p role="status" aria-live="polite">
          <strong>{message}</strong>
        </p>

        {hash && (
          <p style={{ overflowWrap: 'anywhere' }}>
            Computed SHA-256: <code>{hash}</code>
          </p>
        )}

        <p style={{ overflowWrap: 'anywhere' }}>
          Expected SHA-256: <code>{EXPECTED}</code>
        </p>

        <p>
          A match establishes file identity with the published
          release receipt. It does not independently prove
          the tests were executed, authenticate the publisher,
          or rerun the tests.
        </p>
      </div>
    </section>
  );
}
