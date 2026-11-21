import express from 'express';
import { spawn } from 'node:child_process';
import { publishedKeys, verifyAuthenticity } from './reportAuthenticity';

// Independent of accounts, findings storage, scanner readiness and target URLs.
// Raw bytes go only to the offline canonicalization adapter, never to disk/logs.
export function reportVerificationRoutes() {
  const router = express.Router();
  let active = 0;
  const unreadable = (reason: string) => ({
    integrity: { verdict: 'UNREADABLE', reason, algorithm: null, probe_set_version: null },
    authenticity: { verdict: 'UNREADABLE', reason: 'The report could not be evaluated.', key_id: null },
  });
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
      if (output.length > 12 * 1024 * 1024) {
        child.kill('SIGKILL');
        finish(unreadable('Verifier response exceeded its limit.'), 503);
      }
    });
    child.on('error', () => finish(unreadable('Canonical verifier is unavailable.'), 503));
    child.stdin.on('error', () => {}); // Early worker exit is handled by close.
    child.on('close', async code => {
      if (finished) return;
      try {
        const value = JSON.parse(output);
        if (code !== 0 || !['INTACT', 'ALTERED', 'UNREADABLE'].includes(value.verdict)) throw new Error();
        const { verdict, reason, algorithm, probe_set_version } = value;
        const integrity = { verdict, reason, algorithm, probe_set_version };
        const bytes = typeof value.canonical_bytes === 'string'
          ? Buffer.from(value.canonical_bytes, 'base64') : null;
        let authenticity;
        try {
          // Neither answer is derived from the other. Signature verification can
          // succeed even when the stored report_hash is absent or altered.
          const keys = value.signature_present ? await publishedKeys() : [];
          authenticity = verifyAuthenticity(value.signature_present, value.signature, bytes, keys, value.divergence);
        } catch {
          authenticity = { verdict: 'UNREADABLE', reason: 'Public verification keys are unavailable.', key_id: null };
        }
        finish({ integrity, authenticity });
      } catch {
        finish(unreadable('Canonical verifier is unavailable.'), 503);
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
