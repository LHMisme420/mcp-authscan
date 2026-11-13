import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { assessmentInquiryRoutes, inquiryConfig } from '../server/assessmentInquiry';
import { validateInquiry } from '../shared/assessmentInquiry';

const valid = {
  name: 'Synthetic Contact', email: 'test@example.invalid', company: 'Synthetic Example',
  website: 'https://example.invalid', service: 'verification', servers: 1,
  timeframe: 'Next month', scope: 'Synthetic inquiry about one authorized MCP server, no actual testing requested.',
};
async function fixture(t: test.TestContext, options: Parameters<typeof assessmentInquiryRoutes>[0] = {}) {
  let time = 2_000_000;
  const app = express();
  app.use('/contact', assessmentInquiryRoutes({
    now: () => time, origins: () => ['https://site.example'],
    config: () => ({ from: 'sender@example.invalid', to: 'owner@example.invalid' }), ...options,
  }));
  app.use('/api', (_req, res) => res.status(401).json({ error: 'Unauthorized' }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const status = () => fetch(`${base}/contact/assessment/status`);
  const challenge = (await (await status()).json()).challenge;
  time += 2100;
  const post = (data: unknown, origin = 'https://site.example') => fetch(`${base}/contact/assessment`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify(data),
  });
  return { base, status, challenge, post, advance: (ms: number) => { time += ms; } };
}
test('shared validation handles required fields, bounds, enums, URLs and email without rejecting personal domains', () => {
  assert(validateInquiry(valid).value);
  assert(validateInquiry({ ...valid, website: '', email: 'test@gmail.com' }).value);
  for (const fields of [
    { name: '' }, { company: '' }, { email: 'bad' }, { email: 'a@example.com\r\nBcc: b@example.com' },
    { website: 'javascript:alert(1)' }, { website: 'https://user:password@example.com' },
    { scope: 'short' }, { scope: 'x'.repeat(3001) }, { servers: 0 }, { servers: 1001 },
    { servers: 1.5 }, { servers: '1' }, { service: 'invalid' }, { service: '__proto__' },
    { timeframe: '' },
  ]) assert(!validateInquiry({ ...valid, ...fields }).value, JSON.stringify(fields));
  assert(!validateInquiry(null).value);
});
test('unconfigured service reports unavailable and never sends', async t => {
  let calls = 0;
  const f = await fixture(t, { config: () => null, send: async () => { calls++; return 'no'; } });
  const status = await (await f.status()).json();
  assert.equal(status.available, false);
  assert.equal(status.challenge, null);
  assert.notEqual((await f.post({ ...valid, challenge: 'invalid', websiteExtra: '' })).status, 202);
  assert.equal(calls, 0);
});
test('Resend default sender is labeled as test mode and cannot enable production intake', async t => {
  const saved = { from: process.env.ASSESSMENT_EMAIL_FROM, to: process.env.ASSESSMENT_EMAIL_TO, mode: process.env.NODE_ENV };
  try {
    process.env.ASSESSMENT_EMAIL_FROM = 'onboarding@resend.dev';
    process.env.ASSESSMENT_EMAIL_TO = 'owner@example.invalid';
    process.env.NODE_ENV = 'production';
    assert.equal(inquiryConfig(), null);
    process.env.NODE_ENV = 'development';
    assert(inquiryConfig());
    let subject = '';
    const f = await fixture(t, { config: inquiryConfig, send: async message => { subject = message.subject; return 'test-delivery'; } });
    assert.equal((await (await f.status()).json()).testMode, true);
    assert.equal((await f.post({ ...valid, challenge: f.challenge, websiteExtra: '' })).status, 202);
    assert.match(subject, /^\[TEST\]/);
  } finally {
    for (const [key, value] of Object.entries({ ASSESSMENT_EMAIL_FROM: saved.from, ASSESSMENT_EMAIL_TO: saved.to, NODE_ENV: saved.mode })) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});
test('validated inquiry is delivered only to configured recipient and duplicate retries send once', async t => {
  const messages: unknown[] = [];
  const f = await fixture(t, { send: async message => { messages.push(message); return 'synthetic-delivery-id'; } });
  const body = { ...valid, challenge: f.challenge, websiteExtra: '', to: 'attacker@example.invalid' };
  const results = await Promise.all([f.post(body), f.post(body)]);
  for (const r of results) {
    assert.equal(r.status, 202);
    assert.equal(r.headers.get('cache-control'), 'no-store');
    const data = await r.json();
    assert.equal(data.accepted, true);
    assert.match(data.message, /not confirmation of inbox receipt/);
  }
  assert.equal(messages.length, 1);
  const message = messages[0] as { from: string; to: string; replyTo: string; text: string };
  assert.equal(message.to, 'owner@example.invalid');
  assert.equal(message.replyTo, valid.email);
  assert.match(message.text, /not authorization to scan/);
  assert.match(message.text, /MCP Server Security Verification/);
  assert.equal((await fetch(`${f.base}/api/findings`)).status, 401);
  assert.equal((await f.post({ ...body, scope: `${valid.scope} Changed.` })).status, 409);
});
test('provider rejection never returns a success; same details retry uses same idempotency key', async t => {
  const keys: string[] = [];
  const f = await fixture(t, { send: async message => {
    keys.push(message.idempotencyKey);
    if (keys.length === 1) throw new Error('Synthetic provider rejection');
    return 'synthetic-retry-id';
  } });
  const body = { ...valid, challenge: f.challenge, websiteExtra: '' };
  const fail = await f.post(body);
  assert.equal(fail.status, 503);
  assert(!('accepted' in await fail.json()));
  assert.equal((await (await f.status()).json()).available, false);
  f.advance(61_000);
  assert.equal((await f.post(body)).status, 202);
  assert.equal(keys[0], keys[1]);
});
test('rejects cross-origin, malformed and oversized bodies, spam and expired verification', async t => {
  let calls = 0;
  const f = await fixture(t, { send: async () => { calls++; return 'no'; } });
  const body = { ...valid, challenge: f.challenge, websiteExtra: '' };
  assert.equal((await f.post(body, 'https://attacker.example')).status, 403);
  assert.equal((await fetch(`${f.base}/contact/assessment`, { method: 'POST', headers: { Origin: 'https://site.example', 'Content-Type': 'application/json' }, body: '{' })).status, 400);
  assert.equal((await f.post({ ...body, scope: 'x'.repeat(15000) })).status, 413);
  assert.equal((await f.post({ ...body, email: 'bad' })).status, 400);
  assert.equal((await f.post({ ...body, websiteExtra: 'spam' })).status, 400);
  assert.equal((await f.post({ ...body, challenge: `${f.challenge}x` })).status, 400);
  f.advance(31 * 60_000);
  assert.equal((await f.post(body)).status, 400);
  assert.equal(calls, 0);
});
test('signed verification enforces a minimum form time and IP-bound integrity', async t => {
  const f = await fixture(t, { send: async () => 'id' });
  const fresh = (await (await f.status()).json()).challenge;
  assert.equal((await f.post({ ...valid, challenge: fresh, websiteExtra: '' })).status, 400);
  const split = fresh.split('.');
  split[2] = '0'.repeat(64);
  f.advance(3000);
  assert.equal((await f.post({ ...valid, challenge: split.join('.'), websiteExtra: '' })).status, 400);
});
test('limits submission attempts and limits anonymous verification requests', async t => {
  const f = await fixture(t, { send: async () => 'id' });
  for (let i = 0; i < 5; i++) assert.equal((await f.post({})).status, 400);
  assert.equal((await f.post({})).status, 429);
  for (let i = 0; i < 39; i++) assert.equal((await f.status()).status, 200);
  assert.equal((await f.status()).status, 429);
});
