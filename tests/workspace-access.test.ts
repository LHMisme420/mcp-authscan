import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { pool } from '../server/db';
import { accountRoutes } from '../server/accountRoutes';
import { tierRoutes, tokenAuthentication, hashToken } from '../server/tierRoutes';

test('Free scans remain available; paid actions fail closed and owner cleanup stays available', async () => {
  if (process.env.NODE_ENV === 'production') throw new Error('Workspace fixture is development-only.');
  const userId = `workspace_fixture_${randomUUID()}`;
  const account = (await pool.query(
    'INSERT INTO public.vata_accounts(clerk_user_id) VALUES($1) RETURNING *', [userId],
  )).rows[0];
  const app = express();
  app.use(express.json());
  app.use('/api', tokenAuthentication);
  // Test-only session context. This fixture never changes the real app's auth.
  app.use('/api', (req: any, _res, next) => {
    if (!req.account) {
      req.account = { ...account, role: req.get('x-fixture-role') === 'member' ? 'member' : 'owner' };
      req.userId = userId;
      req.authMethod = 'session';
    }
    next();
  });
  app.use('/api', accountRoutes, tierRoutes);
  app.post('/api/scan', (req: any, res) => res.json({ accountId: req.account.id }));
  app.use((error: any, _req: any, res: any, _next: any) => {
    res.status(error.status ?? 500).json({ error: error.message });
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  async function request(path: string, method = 'GET', body?: any, headers: Record<string, string> = {}) {
    const response = await fetch(`${origin}/api${path}`, {
      method, headers: { 'Content-Type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, data: await response.json() };
  }
  try {
    const summary = await request('/account');
    assert.equal(summary.status, 200);
    assert.equal(summary.data.billing.plan, 'free');
    assert.equal(summary.data.billing.available, false);
    assert.deepEqual(summary.data.capabilities, {
      programmaticApi: false, scheduling: false, teamSeats: 1, historyDays: null,
    });
    assert.equal(summary.data.usage.limit, null);

    assert.equal((await request('/scan', 'POST')).status, 200);
    assert.equal((await request('/api-tokens', 'POST', { name: 'Workspace regression fixture' })).status, 503);
    const token = `vata_${randomUUID()}`;
    const key = (await pool.query(
      'INSERT INTO public.vata_api_tokens(account_id,user_id,name,token_hash) VALUES($1,$2,$3,$4) RETURNING id',
      [account.id, userId, 'Preexisting token', hashToken(token)],
    )).rows[0];
    const authorization = `Bearer ${token}`;
    const scan = await request('/scan', 'POST', {}, { authorization });
    assert.equal(scan.status, 503);
    assert.equal((await request('/api-tokens', 'GET', undefined, { authorization })).status, 403);
    assert.equal((await request('/api-tokens', 'POST', { name: 'Denied' }, { 'x-fixture-role': 'member' })).status, 403);
    assert.equal((await request('/team/invites', 'POST', {}, { 'x-fixture-role': 'member' })).status, 403);
    assert.equal((await request(`/api-tokens/${key.id}`, 'DELETE')).status, 200);
    assert.equal((await request('/scan', 'POST', {}, { authorization })).status, 401);

    assert.equal((await request('/schedule-scan', 'POST', {
      target_url: 'https://fixture.example.test',
      frequency: 'once', run_at: new Date(Date.now() + 7 * 86400000).toISOString(),
    })).status, 503);
    const schedule = (await pool.query(
      `INSERT INTO public.vata_scan_schedules(account_id,created_by,target_url,frequency,next_run_at)
       VALUES($1,$2,'https://fixture.example.test','daily',now()+interval '7 days') RETURNING id`,
      [account.id, userId],
    )).rows[0];
    assert.equal((await request('/schedule-scan')).data.schedules.length, 1);
    assert.equal((await request(`/schedule-scan/${schedule.id}`, 'PATCH', { enabled: false })).status, 200);
    assert.equal((await request(`/schedule-scan/${schedule.id}`, 'PATCH', { enabled: true })).status, 503);
    assert.equal((await request(`/schedule-scan/${schedule.id}`, 'DELETE')).status, 200);

    assert.equal((await request('/team/invites', 'POST', {})).status, 503);
    assert.equal((await request('/team')).data.seatsUsed, 1);
  } finally {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await pool.query('DELETE FROM public.vata_accounts WHERE id=$1', [account.id]);
    await pool.end();
  }
});
