import { pool } from './db';
import type { WrittenScope } from '../shared/writtenScope';

export type SavedScope = { timestamp: string; emailReference: string | null };
export async function scopeStorageReady() {
  try {
    await pool.query('SELECT id, payload, submitted_at, email_reference FROM public.vata_assessment_scope_requests LIMIT 0');
    return true;
  } catch { return false; }
}

export async function saveScope(id: string, value: WrittenScope): Promise<SavedScope> {
  // Dedicated sales intake storage; never writes to findings or tenant records.
  const result = await pool.query(
    `INSERT INTO public.vata_assessment_scope_requests (id, payload) VALUES ($1, $2::jsonb)
     ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id
     WHERE vata_assessment_scope_requests.payload = EXCLUDED.payload
     RETURNING submitted_at, email_reference`, [id, JSON.stringify(value)],
  );
  if (!result.rows[0]) throw new Error('SCOPE_REQUEST_CONFLICT');
  return {
    timestamp: new Date(result.rows[0].submitted_at).toISOString(),
    emailReference: result.rows[0].email_reference,
  };
}

export async function markScopeEmailed(id: string, reference: string) {
  const result = await pool.query(
    'UPDATE public.vata_assessment_scope_requests SET email_reference = $2 WHERE id = $1',
    [id, reference],
  );
  if (result.rowCount !== 1) throw new Error('SCOPE_RECEIPT_NOT_SAVED');
}
