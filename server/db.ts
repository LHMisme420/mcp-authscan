import pg from 'pg';

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL, max: 5,
  connectionTimeoutMillis: 3000, query_timeout: 3000, statement_timeout: 3000,
});
pool.on('error', () => console.error('PostgreSQL connection lost; readiness checks will retry.'));

// Read-only contract with the publish-time schema. Never create/migrate tables here.
const requiredColumns = {
  'public.vata_accounts': 'id,clerk_user_id',
  'public.vata_memberships': 'user_id,account_id,label,joined_at',
  'public.vata_scan_usage': 'account_id,month,scans',
  'public.vata_team_invites': 'id,account_id,token_hash,expires_at,used_at,revoked_at',
  'public.vata_api_tokens': 'id,account_id,user_id,name,token_hash,created_at,last_used_at,revoked_at',
  'public.vata_scan_schedules': 'id,account_id,created_by,target_url,frequency,next_run_at,enabled,lease_until,last_run_at,last_error,created_at',
};

export class DatabaseReadinessError extends Error {}

export async function verifyDatabase() {
  const configured = process.env.DATABASE_URL;
  if (!configured) {
    throw new DatabaseReadinessError('DATABASE_URL is missing. Provision PostgreSQL through Publish before starting production.');
  }
  try {
    const url = new URL(configured);
    if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname || !url.pathname.slice(1)) throw new Error();
  } catch {
    throw new DatabaseReadinessError('DATABASE_URL must be a PostgreSQL URL with a host and database name.');
  }
  for (const [table, columns] of Object.entries(requiredColumns)) {
    try {
      // Constant identifiers only, zero application rows returned.
      await pool.query(`SELECT ${columns} FROM ${table} LIMIT 0`);
    } catch (error: any) {
      if (['42P01', '42703', '3F000'].includes(error.code)) {
        throw new DatabaseReadinessError(`PostgreSQL schema is not ready (${table}). Review and apply the development-to-production schema changes through Publish; startup does not run migrations.`);
      }
      if (error.code === '42501') {
        throw new DatabaseReadinessError(`PostgreSQL access denied (${table}). Check the configured database role and permissions.`);
      }
      // Never include pg's raw message: it can contain connection details.
      throw new DatabaseReadinessError('PostgreSQL is unavailable. Check database provisioning, DATABASE_URL, credentials and network access.');
    }
  }
}

export async function accountFor(userId: string) {
  const membership = await pool.query(
    `SELECT a.*, 'member' AS role FROM public.vata_memberships m
     JOIN public.vata_accounts a ON a.id=m.account_id WHERE m.user_id=$1`, [userId],
  );
  if (membership.rows[0]) return membership.rows[0];
  const result = await pool.query(
    `INSERT INTO public.vata_accounts (clerk_user_id) VALUES ($1)
     ON CONFLICT (clerk_user_id) DO UPDATE SET clerk_user_id = EXCLUDED.clerk_user_id
     RETURNING *`, [userId],
  );
  return { ...result.rows[0], role: 'owner' };
}
