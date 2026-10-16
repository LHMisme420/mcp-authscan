import { pool } from './db';
import { oncePerTestEvent } from './testWebhook';

export type BillingReceipt = {
  accountId: string; livemode: boolean; endpoint: string; eventId: string; eventType: string; entity: string;
};

/** Receipts are committed only after SDK processing and canonical reconciliation. */
export async function oncePerBillingEvent(receipt: BillingReceipt, action: () => Promise<void>) {
  if (!receipt.livemode) {
    // Preview keeps its explicitly prepared receipt table; it must not depend
    // on the production-only live billing migration. Scope keys so the two
    // sandbox callbacks and connected accounts cannot suppress each other.
    const scope = JSON.stringify([receipt.accountId, receipt.endpoint]);
    return oncePerTestEvent(`${scope}:${receipt.eventId}`, action, `${scope}:${receipt.entity}`);
  }
  const db = await pool.connect();
  const scope = `${receipt.accountId}:${receipt.livemode ? 'live' : 'test'}`;
  const params = [receipt.accountId, receipt.livemode, receipt.endpoint, receipt.eventId];
  try {
    await db.query('BEGIN');
    await db.query('SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))', [scope, receipt.eventId]);
    await db.query('SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))', [scope, receipt.entity]);
    const prior = await db.query(
      `SELECT 1 FROM public.vata_billing_webhook_receipts
       WHERE stripe_account_id=$1 AND livemode=$2 AND endpoint_url=$3 AND event_id=$4`, params,
    );
    if (prior.rowCount) { await db.query('COMMIT'); return false; }
    await action();
    await db.query(
      `INSERT INTO public.vata_billing_webhook_receipts
       (stripe_account_id,livemode,endpoint_url,event_id,event_type) VALUES($1,$2,$3,$4,$5)`,
      [...params, receipt.eventType],
    );
    await db.query('COMMIT');
    return true;
  } catch (error) {
    await db.query('ROLLBACK');
    throw error;
  } finally { db.release(); }
}
