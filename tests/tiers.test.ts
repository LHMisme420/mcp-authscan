import test from 'node:test';
import assert from 'node:assert/strict';
import { pool } from '../server/db';
import { monthWindow, reserveScan, scanUsage } from '../server/tiers';
import { nextOccurrence } from '../server/scheduler';
import { randomUUID } from 'node:crypto';

test('UTC month boundaries and recurring schedules skip missed occurrences', () => {
  assert.equal(monthWindow(new Date('2026-12-31T23:59:59Z')).resetsAt, '2027-01-01T00:00:00.000Z');
  assert.equal(nextOccurrence('once', new Date()), null);
  assert.equal(nextOccurrence('daily', new Date('2026-01-01Z'), new Date('2026-01-03T12:00Z'))?.toISOString(), '2026-01-04T00:00:00.000Z');
});
test('scan accounting is atomic and unlimited without subscriptions', async () => {
  if (process.env.NODE_ENV === 'production') throw new Error('Quota fixture tests are development-only.');
  const uid = `quota_fixture_${randomUUID()}`;
  const id = (await pool.query('INSERT INTO public.vata_accounts(clerk_user_id) VALUES($1) RETURNING id', [uid])).rows[0].id;
  try {
    const december = new Date('2026-12-01Z');
    await Promise.all(Array.from({ length: 12 }, () => reserveScan(id, december)));
    assert.equal((await scanUsage(id, december)).used, 12);
    assert.equal((await scanUsage(id, december)).limit, null);
    assert.equal((await reserveScan(id, new Date('2027-01-01Z'))).used, 1);
    assert.equal((await scanUsage(id, december)).used, 12);
  } finally {
    await pool.query('DELETE FROM public.vata_accounts WHERE id=$1', [id]);
    await pool.end();
  }
});
