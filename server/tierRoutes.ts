import { Router } from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { pool, accountFor } from './db';
import { requireOwner, TierError, validateTarget } from './tiers';
import { appOrigin } from './appOrigin';
import { requirePro } from './billing';

export const hashToken = (value: string) => createHash('sha256').update(value).digest('hex');
export const tierRoutes = Router();
tierRoutes.param('id', (_req, _res, next, value) => {
  if (!/^[1-9]\d*$/.test(value) || !Number.isSafeInteger(Number(value))) return next(new TierError(400, 'Invalid record ID.'));
  next();
});
async function authorizeWorkspace(req: any, owner = false) {
  if (owner) requireOwner(req.account);
  await requirePro(req.account);
}
async function orgLock(accountId: number, work: (client: any) => Promise<any>) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT id FROM public.vata_accounts WHERE id=$1 FOR UPDATE', [accountId]);
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
export async function tokenAuthentication(req: any, _res: any, next: any) {
  try {
    const authorization = req.get('authorization') ?? '';
    if (!authorization.startsWith('Bearer vata_')) return next();
    const token = authorization.slice(7);
    const found = await pool.query(
      `SELECT t.*, a.clerk_user_id AS owner_id FROM public.vata_api_tokens t
       JOIN public.vata_accounts a ON a.id=t.account_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL`,
      [hashToken(token)],
    );
    const key = found.rows[0];
    if (!key) throw new TierError(401, 'Invalid or revoked API token.');
    const member = key.owner_id === key.user_id || (await pool.query(
      'SELECT 1 FROM public.vata_memberships WHERE account_id=$1 AND user_id=$2', [key.account_id, key.user_id],
    )).rowCount;
    if (!member) throw new TierError(401, 'API token membership has been revoked.');
    const apiPath = req.baseUrl + req.path;
    if (!/^\/api\/(scan(?:\/|$)|schedule-scan(?:\/|$)|findings(?:\/|$)|scans\/mcp(?:\/|$)|threat-intelligence$|reports\/compliance$)/.test(apiPath)) {
      throw new TierError(403, 'This API token is scoped to scanning and finding data.');
    }
    const account = (await pool.query('SELECT * FROM public.vata_accounts WHERE id=$1', [key.account_id])).rows[0];
    req.account = { ...account, role: key.owner_id === key.user_id ? 'owner' : 'member' };
    req.userId = key.user_id;
    req.authMethod = 'api_key';
    await authorizeWorkspace(req);
    await pool.query('UPDATE public.vata_api_tokens SET last_used_at=now() WHERE id=$1', [key.id]);
    next();
  } catch (error) { next(error); }
}

tierRoutes.get('/api-tokens', async (req: any, res) => {
  requireOwner(req.account);
  const result = await pool.query(
    'SELECT id,name,created_at,last_used_at FROM public.vata_api_tokens WHERE account_id=$1 AND revoked_at IS NULL ORDER BY id DESC',
    [req.account.id],
  );
  res.json({ tokens: result.rows });
});
tierRoutes.post('/api-tokens', async (req: any, res) => {
  await authorizeWorkspace(req, true);
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  if (!name || name.length > 80) throw new TierError(400, 'Enter a token name (1–80 characters).');
  const token = `vata_${randomBytes(32).toString('base64url')}`;
  const result = await pool.query(
    'INSERT INTO public.vata_api_tokens(account_id,user_id,name,token_hash) VALUES($1,$2,$3,$4) RETURNING id,name',
    [req.account.id, req.userId, name, hashToken(token)],
  );
  res.status(201).json({ ...result.rows[0], token });
});
tierRoutes.delete('/api-tokens/:id', async (req: any, res) => {
  requireOwner(req.account);
  const result = await pool.query(
    'UPDATE public.vata_api_tokens SET revoked_at=now() WHERE id=$1 AND account_id=$2 RETURNING id',
    [req.params.id, req.account.id],
  );
  if (!result.rowCount) throw new TierError(404, 'Token not found.');
  res.json({ revoked: true });
});

tierRoutes.get('/team', async (req: any, res) => {
  const account = req.account;
  const members = await pool.query('SELECT user_id AS "userId",label,joined_at FROM public.vata_memberships WHERE account_id=$1 ORDER BY joined_at', [account.id]);
  const invites = account.role === 'owner' ? (await pool.query(
    'SELECT id,expires_at FROM public.vata_team_invites WHERE account_id=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>now()',
    [account.id],
  )).rows : [];
  const pendingCount = (await pool.query(
    'SELECT count(*) AS count FROM public.vata_team_invites WHERE account_id=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>now()',
    [account.id],
  )).rows[0].count;
  res.json({
    role: account.role, organization: { id: -account.id, name: account.display_name },
    seatsUsed: 1 + members.rows.length + Number(pendingCount), maxSeats: 5,
    members: [{ userId: account.clerk_user_id, role: 'owner', label: 'Organization owner' },
      ...members.rows.map(member => ({ ...member, role: 'member' }))], invites,
  });
});
tierRoutes.post('/team/invites', async (req: any, res) => {
  await authorizeWorkspace(req, true);
  const token = randomBytes(32).toString('base64url');
  const invite = await orgLock(req.account.id, async client => {
    const seats = await client.query(
      `SELECT 1+(SELECT count(*) FROM public.vata_memberships WHERE account_id=$1)+
       (SELECT count(*) FROM public.vata_team_invites WHERE account_id=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>now()) AS used`,
      [req.account.id],
    );
    if (Number(seats.rows[0].used) >= 5) throw new TierError(403, 'All 5 team seats are occupied or reserved.');
    return (await client.query(
      `INSERT INTO public.vata_team_invites(account_id,token_hash,expires_at) VALUES($1,$2,now()+interval '7 days')
       RETURNING id,expires_at`, [req.account.id, hashToken(token)],
    )).rows[0];
  });
  res.status(201).json({ ...invite, invite_url: `${appOrigin()}/join-team?token=${encodeURIComponent(token)}` });
});
tierRoutes.delete('/team/invites/:id', async (req: any, res) => {
  requireOwner(req.account);
  const result = await pool.query(
    'UPDATE public.vata_team_invites SET revoked_at=now() WHERE id=$1 AND account_id=$2 RETURNING id',
    [req.params.id, req.account.id],
  );
  if (!result.rowCount) throw new TierError(404, 'Invitation not found.');
  res.json({ revoked: true });
});
tierRoutes.post('/team/join', async (req: any, res) => {
  const token = req.body?.token;
  if (typeof token !== 'string' || token.length > 100) throw new TierError(400, 'Invalid invitation.');
  const invite = (await pool.query(
    'SELECT * FROM public.vata_team_invites WHERE token_hash=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>now()',
    [hashToken(token)],
  )).rows[0];
  if (!invite) throw new TierError(404, 'Invitation is invalid, expired or already used.');
  if (req.account.role === 'member') throw new TierError(409, 'Leave your current team before joining another.');
  const personal = await accountFor(req.userId);
  if ((await pool.query(
    'SELECT 1 FROM public.vata_memberships WHERE account_id=$1 LIMIT 1', [personal.id],
  )).rowCount) throw new TierError(409, 'Owners of a team must resolve that workspace before joining another.');
  const target = (await pool.query('SELECT * FROM public.vata_accounts WHERE id=$1', [invite.account_id])).rows[0];
  await requirePro(target);
  if (target.clerk_user_id === req.userId) throw new TierError(409, 'You already own this organization.');
  await orgLock(target.id, async client => {
    const current = (await client.query(
      'SELECT * FROM public.vata_team_invites WHERE id=$1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at>now() FOR UPDATE',
      [invite.id],
    )).rows[0];
    if (!current) throw new TierError(409, 'Invitation has already been used or revoked.');
    const seats = await client.query('SELECT count(*) AS used FROM public.vata_memberships WHERE account_id=$1', [target.id]);
    if (Number(seats.rows[0].used) >= 4) throw new TierError(403, 'The organization already has 5 users.');
    await client.query('INSERT INTO public.vata_memberships(user_id,account_id,label) VALUES($1,$2,$3)',
      [req.userId, target.id, `Member ${req.userId.slice(-8)}`]);
    await client.query('UPDATE public.vata_team_invites SET used_at=now() WHERE id=$1', [invite.id]);
  });
  res.json({ joined: true, organization: { id: -target.id, name: target.display_name } });
});
async function removeMembership(accountId: number, userId: string) {
  return orgLock(accountId, async client => {
    const result = await client.query('DELETE FROM public.vata_memberships WHERE account_id=$1 AND user_id=$2 RETURNING user_id', [accountId, userId]);
    if (!result.rowCount) throw new TierError(404, 'Team member not found.');
    await client.query('UPDATE public.vata_api_tokens SET revoked_at=now() WHERE account_id=$1 AND user_id=$2', [accountId, userId]);
    await client.query('UPDATE public.vata_scan_schedules SET enabled=false WHERE account_id=$1 AND created_by=$2', [accountId, userId]);
  });
}
tierRoutes.delete('/team/members/:userId', async (req: any, res) => {
  requireOwner(req.account);
  await removeMembership(req.account.id, String(req.params.userId));
  res.json({ removed: true });
});
tierRoutes.post('/team/leave', async (req: any, res) => {
  if (req.account.role !== 'member') throw new TierError(403, 'Owners cannot leave their own organization.');
  await removeMembership(req.account.id, req.userId);
  res.json({ left: true });
});

tierRoutes.get('/schedule-scan', async (req: any, res) => {
  res.json({ schedules: (await pool.query(
    'SELECT id,created_by,target_url,frequency,next_run_at,enabled,last_run_at,last_error FROM public.vata_scan_schedules WHERE account_id=$1 ORDER BY id DESC',
    [req.account.id],
  )).rows });
});
tierRoutes.post('/schedule-scan', async (req: any, res) => {
  await authorizeWorkspace(req);
  const target = validateTarget(req.body);
  const frequency = req.body.frequency ?? 'daily';
  if (!['once', 'hourly', 'daily', 'weekly'].includes(frequency)) throw new TierError(400, 'Choose once, hourly, daily or weekly.');
  const runAt = req.body.run_at ? new Date(req.body.run_at) : new Date(Date.now() + 60000);
  if (!Number.isFinite(runAt.getTime()) || runAt.getTime() < Date.now() - 1000) throw new TierError(400, 'Choose a future UTC start time.');
  const result = await pool.query(
    `INSERT INTO public.vata_scan_schedules(account_id,created_by,target_url,frequency,next_run_at)
     VALUES($1,$2,$3,$4,$5) RETURNING *`, [req.account.id, req.userId, target, frequency, runAt],
  );
  res.status(201).json({ schedule: result.rows[0] });
});
tierRoutes.patch('/schedule-scan/:id', async (req: any, res) => {
  if (typeof req.body.enabled !== 'boolean') throw new TierError(400, 'enabled must be a boolean.');
  if (req.body.enabled) await authorizeWorkspace(req);
  const result = await pool.query(
    `UPDATE public.vata_scan_schedules SET enabled=$1,next_run_at=CASE WHEN $1 THEN greatest(next_run_at,now()) ELSE next_run_at END
     WHERE id=$2 AND account_id=$3 AND ($4='owner' OR created_by=$5) RETURNING *`,
    [req.body.enabled, req.params.id, req.account.id, req.account.role, req.userId],
  );
  if (!result.rowCount) throw new TierError(404, 'Schedule not found or not editable.');
  res.json({ schedule: result.rows[0] });
});
tierRoutes.delete('/schedule-scan/:id', async (req: any, res) => {
  const result = await pool.query(
    `DELETE FROM public.vata_scan_schedules WHERE id=$1 AND account_id=$2 AND ($3='owner' OR created_by=$4) RETURNING id`,
    [req.params.id, req.account.id, req.account.role, req.userId],
  );
  if (!result.rowCount) throw new TierError(404, 'Schedule not found or not editable.');
  res.json({ deleted: true });
});
