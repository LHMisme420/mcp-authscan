import express from 'express';
import { spawn } from 'node:child_process';

// Every verdict comes from the Python engine (mcp_authscan.verification), run offline by
// `python3 -m mcp_authscan.verify_upload` with the packaged, SHA-256-pinned key history.
// This route only validates the engine's JSON shape and reshapes it; it verifies nothing.
// Independent of accounts, findings storage, scanner readiness and target URLs.
// Raw bytes go only to the engine's stdin, never to disk/logs.

export const AUTHENTICITY_VERDICTS = [
  'SIGNED BY', 'NOT SIGNED', 'SIGNATURE INVALID', 'UNKNOWN KEY', 'KEY NOT VALID', 'DIVERGENCE',
  'UNSUPPORTED FORM', 'UNREADABLE', 'UNAVAILABLE',
] as const;
const STAGES = ['catalog', 'format', 'integrity', 'authenticity'];
const ENGINE = 'mcp-authscan-verify/1';

type Engine = Record<string, any>;
const str = (value: unknown) => typeof value === 'string';
const strOrNull = (value: unknown) => typeof value === 'string' || value === null;

/** The engine result reshaped for the browser, or null if it is not a well-formed engine result. */
export function shapeEngineResult(value: Engine): { status: number; body: object } | null {
  if (!value || typeof value !== 'object' || value.engine !== ENGINE ||
      !(value.failed_stage === null || STAGES.includes(value.failed_stage))) return null;
  const { catalog, format, integrity, authenticity, probe_statuses: probes } = value;
  if (!catalog || !str(catalog.verdict) || !str(catalog.reason ?? '') || !format || !integrity ||
      !authenticity || !probes || !str(probes.verdict) || !str(probes.reason)) return null;
  if (value.failed_stage === 'catalog') {
    // A server-side fault, never a verdict about the uploaded report.
    return { status: 503, body: unreadable('Probe-set catalog failed its pinned digest; verification is unavailable.') };
  }
  // attestation is null when the format stage failed before the probe set could be read.
  if (!str(catalog.sha256) || !strOrNull(catalog.attestation)) return null;
  const meta = {
    probe_statuses: { verdict: probes.verdict, reason: probes.reason },
    catalog: { sha256: catalog.sha256, attestation: catalog.attestation },
    failed_stage: value.failed_stage,
  };
  if (!strOrNull(format.algorithm) || !strOrNull(format.probe_set_version) || !str(format.reason)) return null;
  if (value.failed_stage === 'format') {
    return { status: 200, body: {
      integrity: { verdict: 'UNREADABLE', reason: format.reason, algorithm: format.algorithm,
                   probe_set_version: format.probe_set_version },
      authenticity: { verdict: 'UNREADABLE', reason: 'The report could not be evaluated.', key_id: null },
      ...meta,
    } };
  }
  if (!['INTACT', 'ALTERED'].includes(integrity.verdict) || !str(integrity.reason) ||
      !AUTHENTICITY_VERDICTS.includes(authenticity.verdict) || !str(authenticity.reason) ||
      !strOrNull(authenticity.key_id)) return null;
  return { status: 200, body: {
    integrity: { verdict: integrity.verdict, reason: integrity.reason, algorithm: format.algorithm,
                 probe_set_version: format.probe_set_version },
    authenticity: { verdict: authenticity.verdict, reason: authenticity.reason, key_id: authenticity.key_id },
    ...meta,
  } };
}

function unreadable(reason: string) {
  return {
    integrity: { verdict: 'UNREADABLE', reason, algorithm: null, probe_set_version: null },
    authenticity: { verdict: 'UNREADABLE', reason: 'The report could not be evaluated.', key_id: null },
  };
}

export function reportVerificationRoutes() {
  const router = express.Router();
  let active = 0;
  router.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  router.post('/verify', express.text({ type: 'application/json', limit: '1mb' }), (req, res) => {
    if (!req.is('application/json') || typeof req.body !== 'string') {
      res.status(415).json(unreadable('Send the JSON report as application/json.'));
      return;
    }
    if (active >= 4) {
      res.status(429).json(unreadable('Verifier is busy. Please retry.'));
      return;
    }
    active++;
    const child = spawn('python3', ['-m', 'mcp_authscan.verify_upload'], {
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    let output = '';
    let finished = false;
    const finish = (value: object, status = 200) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      active--;
      if (!res.destroyed) res.status(status).json(value);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(unreadable('Verification exceeded its time limit.'), 503);
    }, 5000);
    child.stdout.on('data', chunk => {
      output += chunk.toString();
      if (output.length > 256 * 1024) {
        child.kill('SIGKILL');
        finish(unreadable('Verifier response exceeded its limit.'), 503);
      }
    });
    child.on('error', () => finish(unreadable('Verification engine is unavailable.'), 503));
    child.stdin.on('error', () => {}); // Early worker exit is handled by close.
    child.on('close', code => {
      if (finished) return;
      try {
        if (code !== 0) throw new Error();
        const shaped = shapeEngineResult(JSON.parse(output));
        if (!shaped) throw new Error();
        finish(shaped.body, shaped.status);
      } catch {
        finish(unreadable('Verification engine is unavailable.'), 503);
      }
    });
    child.stdin.end(req.body);
  });
  router.use((error: any, _req: any, res: any, _next: any) => {
    res.status(error?.type === 'entity.too.large' ? 413 : 400)
      .json(unreadable(error?.type === 'entity.too.large'
        ? 'Report exceeds the 1 MiB limit.' : 'Report request could not be read.'));
  });
  return router;
}
