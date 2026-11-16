import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { assessmentInquiryRoutes } from '../server/assessmentInquiry';
import { scopeAuthorization, scopeEmailText, validateWrittenScope } from '../shared/writtenScope';

const value = {
  name: 'Synthetic Requester', email: 'tester@example.invalid', company: 'Synthetic Example',
  endpoints: 'https://one.example.invalid/mcp\nhttps://two.example.invalid/mcp',
  service: 'comprehensive', authority: 'We own both endpoints and can approve testing.',
  environment: '', authorized: true,
};

async function fixture(t: test.TestContext, overrides: Parameters<typeof assessmentInquiryRoutes>[0] = {}) {
  let time = 1_000_000, sends = 0, saves = 0, marked = 0;
  let message = '', savedValue: unknown;
  const app = express();
  app.use('/contact', assessmentInquiryRoutes({
    kind: 'scope', now: () => time, origins: () => ['https://scope.example'],
    config: () => ({ from: 'assessments@example.invalid', to: 'lhmisme2011@gmail.com' }),
    storageReady: async () => true,
    save: async (_id, data) => {
      saves++; savedValue = data;
      return { timestamp: '2026-11-16T12:34:56.000Z', emailReference: null };
    },
    send: async data => { sends++; message = data.text; return 'synthetic-email-id'; },
    markEmailed: async () => { marked++; },
    ...overrides,
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/contact/scope`;
  const status = () => fetch(`${base}/status`);
  const challenge = (await (await status()).json()).challenge;
  time += 2100;
  const post = (data: unknown, origin = 'https://scope.example') => fetch(base, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin }, body: JSON.stringify(data),
  });
  return {
    post, status, data: { ...value, websiteExtra: '', challenge },
    counters: () => ({ sends, saves, marked, message, savedValue }),
  };
}

test('required scope fields, option and explicit authority are independently validated', () => {
  assert(validateWrittenScope(value).value);
  for (const invalid of [
    { authorized: false }, { authorized: 'true' }, { authority: '' }, { endpoints: '' },
    { name: '' }, { email: 'bad' }, { email: 'a@b.com\r\nBcc:x@y.com' }, { company: '' },
    { service: 'publication' }, { service: '__proto__' }, { endpoints: 'x\n\ny' },
    { environment: 'x'.repeat(2001) },
  ]) assert(!validateWrittenScope({ ...value, ...invalid }).value, JSON.stringify(invalid));
  assert(!validateWrittenScope(null).value);
});

test('save precedes sending, email contains every field and durable timestamp, duplicate submits reuse send', async t => {
  const f = await fixture(t);
  const response = await f.post(f.data);
  assert.equal(response.status, 201);
  const result = await response.json();
  assert.equal(result.saved, true);
  assert.equal(result.emailed, true);
  assert.equal(result.timestamp, '2026-11-16T12:34:56.000Z');
  assert.match(result.message, /No testing happens until you approve it/);
  assert.match(result.message, /written scope will follow/);
  const { saves, sends, marked, message, savedValue } = f.counters();
  assert.equal(saves, 1); assert.equal(sends, 1); assert.equal(marked, 1);
  assert.deepEqual(savedValue, value);
  for (const field of [value.name, value.email, value.company, value.endpoints, value.authority, scopeAuthorization, result.timestamp]) assert(message.includes(field));
  assert.match(message, /Full assessment, 3,500 dollars/);
  assert.equal((await f.post(f.data)).status, 201);
  assert.equal(f.counters().sends, 1);
  assert.equal((await f.post({ ...f.data, company: 'Different' })).status, 409);
});

test('authority checkbox and cross-origin requests cannot reach storage or mail', async t => {
  const f = await fixture(t);
  assert.equal((await f.post({ ...f.data, authorized: false })).status, 400);
  assert.equal((await f.post(f.data, 'https://untrusted.example')).status, 403);
  assert.equal((await f.post({ ...f.data, challenge: 'fake' })).status, 400);
  assert.equal(f.counters().saves, 0);
  assert.equal(f.counters().sends, 0);
});

test('a storage failure sends no email and shows no success', async t => {
  const f = await fixture(t, { save: async () => { throw new Error('storage unavailable'); } });
  const response = await f.post(f.data);
  assert.equal(response.status, 503);
  assert.equal((await response.json()).saved, undefined);
  assert.equal(f.counters().sends, 0);
});

test('email failure retains saved request but does not claim submission success', async t => {
  const f = await fixture(t, { send: async () => { throw new Error('mail unavailable'); } });
  const response = await f.post(f.data);
  assert.equal(response.status, 503);
  const result = await response.json();
  assert.match(result.error, /may have been saved/);
  assert.equal(result.emailed, undefined);
  assert.equal(f.counters().saves, 1);
  assert.equal(f.counters().marked, 0);
});

test('missing config, wrong recipient or missing storage marks service unavailable', async t => {
  for (const options of [
    { config: () => null },
    { storageReady: async () => false },
    { config: () => ({ from: 'sender@example.invalid', to: 'wrong@example.invalid' }) },
  ]) {
    const f = await fixture(t, options);
    const status = await (await f.status()).json();
    assert.equal(status.available, false);
    assert.equal(status.challenge, null);
  }
});

test('already emailed durable request does not send again after process-local replay state is lost', async t => {
  const f = await fixture(t, {
    save: async () => ({ timestamp: '2026-11-16T00:00:00.000Z', emailReference: 'already-accepted' }),
  });
  const response = await f.post(f.data);
  assert.equal(response.status, 201);
  assert.equal((await response.json()).reference, 'already-accepted');
  assert.equal(f.counters().sends, 0);
});

test('provided optional environment appears in plain text without HTML interpretation', () => {
  const text = scopeEmailText({ ...value, service: 'verification', environment: '<script>synthetic</script>' }, '2026-11-16T00:00:00Z');
  assert.match(text, /Single server, 1,750 dollars/);
  assert.match(text, /<script>synthetic<\/script>/);
});
