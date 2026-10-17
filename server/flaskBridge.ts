import jwt from 'jsonwebtoken';
import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import { accountFor } from './db';
import { reserveScan, scanUsage, validateTarget } from './tiers';
import { withFindingsStorage } from './findingsStorage';

export function configuredPort(value: string | undefined, fallback: number) {
  if (value === undefined) return fallback;
  const port = Number(value);
  if (!/^\d+$/.test(value) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Application port configuration must be an integer from 1 to 65535.');
  }
  return port;
}
export const SCANNER_PORT = configuredPort(process.env.VATA_SCANNER_PORT, 5001);
export const FLASK_ORIGIN = `http://127.0.0.1:${SCANNER_PORT}`;

export async function scannerReady() {
  try {
    const response = await fetch(`${FLASK_ORIGIN}/health`, {
      signal: AbortSignal.timeout(1500), redirect: 'error',
    });
    return response.ok && (await response.json()).status === 'ok';
  } catch {
    return false;
  }
}

export async function waitForScanner(isStopped: () => boolean, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  while (!isStopped()) {
    // Probe once more even if a suspended process resumes past its deadline.
    // An already-ready scanner must not be killed merely because a timer ran late.
    if (await scannerReady()) return;
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await new Promise(resolve => setTimeout(resolve, Math.min(100, remaining)));
  }
  throw new Error('Private scanner did not become ready. Check Gunicorn, Python dependencies and DB_FILE access.');
}
export function bridgeToken(account: any, context: any = {}) {
  const secret = process.env.JWT_SECRET || process.env.SESSION_SECRET;
  if (!secret) throw new Error('ACCOUNT_BRIDGE_SECRET_MISSING');
  return jwt.sign({
    sub: String(-account.id), type: 'access', fresh: false,
    jti: randomUUID(), bridge: true, owner_user_id: account.clerk_user_id,
    ...context,
  }, secret, { algorithm: 'HS256', expiresIn: 60 });
}

export async function proxyScanner(req: any, res: any) {
  const account = req.account ?? await accountFor(req.userId);
  const scanning = req.method === 'POST' && ['/api/scan', '/api/scans/mcp'].includes(req.path);
  if (scanning) validateTarget(req.body);
  const usage = scanning ? await reserveScan(account.id) : await scanUsage(account.id);
  const result = await callScanner(account, usage, scanning,
    scanning ? '/api/scans/mcp' : req.originalUrl, req.method, req.body);
  if (result.pdf) {
    res.status(result.status).setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="vata-compliance-summary.pdf"');
    res.send(result.pdf);
    return;
  }
  res.status(result.status).json(result.data);
}

export async function callScanner(account: any, usage: any, scanning: boolean,
  apiPath: string, method: string, body?: any) {
  return withFindingsStorage(() => callScannerUnprotected(account, usage, scanning, apiPath, method, body));
}

async function callScannerUnprotected(account: any, usage: any, scanning: boolean,
  apiPath: string, method: string, body?: any) {
  const authorization = `Bearer ${bridgeToken(account, {
    monthly_scan_count: usage.used, scan_count_month: usage.month, scan_authorized: scanning,
  })}`;
  const provisioned = await fetch(`${FLASK_ORIGIN}/internal/provision`, {
    method: 'POST', headers: { Authorization: authorization }, signal: AbortSignal.timeout(10000),
  });
  if (!provisioned.ok) return { status: provisioned.status, data: { error: 'Workspace provisioning failed.' } };
  const response = await fetch(`${FLASK_ORIGIN}${apiPath}`, {
    method,
    headers: { Authorization: authorization, 'Content-Type': 'application/json' },
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(120000), redirect: 'error',
  });
  return decodeScannerResponse(response);
}

export async function decodeScannerResponse(response: Response): Promise<
  { status: number; data: unknown; pdf?: never } | { status: number; pdf: Buffer; data?: never }
> {
  if (response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() === 'application/pdf') {
    return { status: response.status, pdf: Buffer.from(await response.arrayBuffer()) };
  }
  return { status: response.status, data: await response.json() };
}
