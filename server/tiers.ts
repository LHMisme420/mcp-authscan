import { pool } from './db';

export class TierError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export function monthWindow(now = new Date()) {
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
  return { month: start.toISOString().slice(0, 7), date: start.toISOString().slice(0, 10), resetsAt: end.toISOString() };
}
export async function scanUsage(accountId: number, now = new Date()) {
  const window = monthWindow(now);
  const result = await pool.query(
    'SELECT scans FROM public.vata_scan_usage WHERE account_id=$1 AND month=$2', [accountId, window.date],
  );
  const used = result.rows[0]?.scans ?? 0;
  return { used, limit: null, remaining: null, month: window.month, resetsAt: window.resetsAt };
}
export async function reserveScan(accountId: number, now = new Date()) {
  const window = monthWindow(now);
  const result = await pool.query(
    `INSERT INTO public.vata_scan_usage (account_id,month,scans) VALUES ($1,$2,1)
     ON CONFLICT (account_id,month) DO UPDATE SET scans=vata_scan_usage.scans+1
     RETURNING scans`,
    [accountId, window.date],
  );
  return { used: result.rows[0].scans, month: window.month };
}
export function requireOwner(account: any) {
  if (account.role !== 'owner') throw new TierError(403, 'Only the organization owner can manage this feature.');
}
export function validateTarget(body: any) {
  const target = body?.target_url || body?.url;
  if (typeof target !== 'string' || !target.trim() || target.length > 2048) {
    throw new TierError(400, 'Enter a valid MCP server URL.');
  }
  let url: URL;
  try { url = new URL(target.trim()); } catch { throw new TierError(400, 'Enter a valid MCP server URL.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) {
    throw new TierError(400, 'Use an HTTP(S) server URL without embedded credentials.');
  }
  if (body.timeout !== undefined && (!Number.isInteger(body.timeout) || body.timeout < 1 || body.timeout > 15)) {
    throw new TierError(400, 'Timeout must be between 1 and 15 seconds.');
  }
  return url.toString();
}
