import { pool } from './db';
import { callScanner } from './flaskBridge';
import { reserveScan } from './tiers';
import { requirePro } from './billing';

export function nextOccurrence(frequency: string, previous: Date, now = new Date()) {
  if (frequency === 'once') return null;
  const milliseconds = { hourly: 3600000, daily: 86400000, weekly: 604800000 }[frequency];
  if (!milliseconds) throw new Error('Invalid schedule frequency.');
  const periods = Math.max(1, Math.floor((now.getTime() - previous.getTime()) / milliseconds) + 1);
  return new Date(previous.getTime() + periods * milliseconds);
}
export async function runDueSchedule() {
  const result = await pool.query(
    `UPDATE public.vata_scan_schedules SET lease_until=now()+interval '5 minutes'
     WHERE id=(SELECT id FROM public.vata_scan_schedules WHERE enabled AND next_run_at<=now()
       AND (lease_until IS NULL OR lease_until<now()) ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT 1)
     RETURNING *`,
  );
  const job = result.rows[0];
  if (!job) return false;
  let error: string | null = null;
  let next = nextOccurrence(job.frequency, new Date(job.next_run_at));
  let started = false;
  try {
    const account = (await pool.query('SELECT * FROM public.vata_accounts WHERE id=$1', [job.account_id])).rows[0];
    const authorized = account.clerk_user_id === job.created_by || (await pool.query(
      'SELECT 1 FROM public.vata_memberships WHERE account_id=$1 AND user_id=$2', [job.account_id, job.created_by],
    )).rowCount;
    if (!authorized) throw new Error('Schedule creator is no longer a member.');
    await requirePro(account);
    const usage = await reserveScan(account.id);
    started = true;
    const response = await callScanner(account, usage, true, '/api/scans/mcp', 'POST', { target_url: job.target_url });
    if (response.status >= 400) error = 'Scheduled scan failed. Check target availability and scan history.';
  } catch {
    error = 'Scan postponed: verify Pro subscription, membership, and scanner availability.';
    next = new Date(Date.now() + 300000);
  } finally {
    await pool.query(
      `UPDATE public.vata_scan_schedules SET lease_until=NULL,last_error=$1,
       last_run_at=CASE WHEN $2 THEN now() ELSE last_run_at END,
       enabled=CASE WHEN $3::timestamptz IS NULL THEN false ELSE enabled END,
       next_run_at=coalesce($3,next_run_at) WHERE id=$4`,
      [error, started, next, job.id],
    );
  }
  return true;
}
export function startScheduler() {
  let busy = false;
  let stopped = false;
  const timer = setInterval(async () => {
    if (busy || stopped) return;
    busy = true;
    try { await runDueSchedule(); } catch { if (!stopped) console.error('Schedule worker failed; durable jobs will retry.'); }
    finally { busy = false; }
  }, 15000);
  timer.unref();
  return () => { stopped = true; clearInterval(timer); };
}
