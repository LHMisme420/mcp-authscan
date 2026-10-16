import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import net from 'node:net';
import Stripe from 'stripe';

test('Preview billing reconciles signed events with only the prepared test receipt schema', { timeout: 120000 }, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'vata-preview-hook-'));
  const data = path.join(directory, 'postgres');
  const socket = net.createServer();
  await new Promise<void>(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = (socket.address() as net.AddressInfo).port;
  await new Promise<void>(resolve => socket.close(() => resolve()));
  const tools = { PATH: process.env.PATH!, HOME: process.env.HOME!, LANG: 'C.UTF-8' };
  const tool = (name: string, args: string[]) =>
    execFileSync(name, args, { env: tools, stdio: ['ignore', 'pipe', 'pipe'] });
  const previous = {
    DATABASE_URL: process.env.DATABASE_URL, NODE_ENV: process.env.NODE_ENV,
    VATA_BILLING_MODE: process.env.VATA_BILLING_MODE,
  };
  let started = false;
  let database: (typeof import('../server/db'))['pool'] | undefined;
  t.after(async () => {
    try {
      await database?.end();
    } finally {
      try {
        if (started) tool('pg_ctl', ['-D', data, '-m', 'immediate', '-w', 'stop']);
      } finally {
        await rm(directory, { recursive: true, force: true });
        for (const [key, value] of Object.entries(previous)) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
      }
    }
  });
  tool('initdb', ['-D', data, '-A', 'trust', '-U', 'fixture_owner', '--no-locale']);
  tool('pg_ctl', ['-D', data, '-l', path.join(directory, 'postgres.log'),
    '-o', `-h 127.0.0.1 -p ${port} -k ${directory}`, '-w', 'start']);
  started = true;
  // The test worker is a separate process. Only the synthetic database URL is
  // given to the actual receipt processor; no workspace database is touched.
  process.env.DATABASE_URL = `postgresql://fixture_owner@127.0.0.1:${port}/postgres`;
  process.env.NODE_ENV = 'development';
  delete process.env.VATA_BILLING_MODE;
  database = (await import('../server/db')).pool;
  await database.query(await readFile('migrations/test-webhook-receipts.sql', 'utf8'));
  assert.equal((await database.query(
    "SELECT to_regclass('public.vata_billing_webhook_receipts') AS live_table",
  )).rows[0].live_table, null, 'Preview must not require the production migration.');

  const { createBillingWebhookProcessor } = await import('../server/webhookHandlers');
  const stripe = new Stripe('sk_test_synthetic_fixture');
  const signingSecret = 'whsec_synthetic_fixture_only';
  let syncCalls = 0, refreshCalls = 0, closes = 0, fail = false;
  let endpoint = 'https://preview.example.test/api/stripe/webhook';
  let accountId = 'acct_previewfixture';
  const processor = createBillingWebhookProcessor(async () => ({
    accountId, endpoint, mode: 'test',
    verify: (payload, signature) => stripe.webhooks.constructEventAsync(payload, signature, signingSecret),
    sync: async () => ({
      processWebhook: async () => {
        if (fail) throw new Error('Synthetic reconciliation failure');
        syncCalls++;
      },
      syncSingleEntity: async id => {
        assert.equal(id, 'sub_previewfixture');
        refreshCalls++;
      },
      postgresClient: { pool: { end: async () => { closes++; } } },
    }),
  }));
  async function send(id: string, secret = signingSecret, livemode = false) {
    const payload = JSON.stringify({
      id, livemode, type: 'customer.subscription.deleted',
      data: { object: { id: 'sub_previewfixture', status: 'canceled' } },
    });
    const signature = stripe.webhooks.generateTestHeaderString({ payload, secret });
    await processor(Buffer.from(payload), signature);
  }
  await Promise.all(Array.from({ length: 3 }, () => send('evt_previewfixture')));
  assert.equal(syncCalls, 1, 'Real database locks and receipts deduplicate concurrent events.');
  assert.equal(refreshCalls, 1, 'Terminal state is canonically refreshed before receipt commit.');
  assert.equal((await database.query('SELECT count(*)::int AS count FROM public.vata_test_webhook_receipts')).rows[0].count, 1);
  await assert.rejects(send('evt_previewfixture', 'whsec_wrong_fixture'));
  await assert.rejects(send('evt_wrongmode', signingSecret, true));
  assert.equal(syncCalls, 1, 'Replay authentication and mode validation precede receipt lookup.');
  fail = true;
  await assert.rejects(send('evt_retryfixture'));
  assert.equal((await database.query('SELECT count(*)::int AS count FROM public.vata_test_webhook_receipts')).rows[0].count, 1);
  fail = false;
  await send('evt_retryfixture');
  assert.equal(syncCalls, 2);
  endpoint = 'https://other-preview.example.test/api/stripe/webhook';
  await send('evt_previewfixture');
  accountId = 'acct_otherfixture';
  await send('evt_previewfixture');
  assert.equal(syncCalls, 4, 'Accounts and callback URLs have independent receipt scopes.');
  assert.equal(refreshCalls, 4);
  assert.equal(closes, 7, 'Every created SDK connection is closed, including duplicates and failures.');
  assert.equal((await database.query('SELECT count(*)::int AS count FROM public.vata_test_webhook_receipts')).rows[0].count, 4);
});
