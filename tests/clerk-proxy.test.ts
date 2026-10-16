import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import http, { type IncomingHttpHeaders, type RequestListener, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
import express from 'express';
import { clerkProxyMiddleware, CLERK_PROXY_PATH, getClerkProxyHost } from '../server/middlewares/clerkProxyMiddleware';

async function listen(t: TestContext, server: Server) {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function fixture(t: TestContext, upstream: RequestListener, environment = 'production', secret = 'synthetic-proxy-secret') {
  const previous = { NODE_ENV: process.env.NODE_ENV, CLERK_SECRET_KEY: process.env.CLERK_SECRET_KEY };
  process.env.NODE_ENV = environment;
  if (secret) process.env.CLERK_SECRET_KEY = secret;
  else delete process.env.CLERK_SECRET_KEY;
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  const target = await listen(t, http.createServer(upstream));
  const app = express();
  app.use(CLERK_PROXY_PATH, clerkProxyMiddleware(target));
  app.use((_req, res) => res.status(418).end('not proxied'));
  return { target, origin: await listen(t, http.createServer(app)) };
}

function request(url: string, method = 'GET', headers: IncomingHttpHeaders = {}, body?: string) {
  return new Promise<{ status: number; headers: IncomingHttpHeaders; body: Buffer }>((resolve, reject) => {
    const req = http.request(url, { method, headers }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.setTimeout(3000, () => req.destroy(new Error('proxy request timed out')));
    req.end(body);
  });
}

test('Clerk host selection preserves forwarded hosts and ordinary Host fallback', () => {
  assert.equal(getClerkProxyHost({ headers: { 'x-forwarded-host': 'public.example.test, internal.test', host: 'internal.test' } }), 'public.example.test');
  assert.equal(getClerkProxyHost({ headers: { 'x-forwarded-host': ['public.example.test', 'internal.test'] } }), 'public.example.test');
  assert.equal(getClerkProxyHost({ headers: { host: 'public.example.test' } }), 'public.example.test');
});

test('Clerk proxy preserves method, raw body, query, cookies and trusted forwarding headers', async t => {
  const received: { url?: string; headers?: IncomingHttpHeaders; body?: string; method?: string } = {};
  const { origin, target } = await fixture(t, (req, res) => {
    received.url = req.url;
    received.method = req.method;
    received.headers = req.headers;
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      received.body = body;
      res.setHeader('set-cookie', ['first=synthetic; Path=/', 'second=synthetic; Path=/']);
      res.write('chunked ');
      res.end('response');
    });
  });
  const body = '{"synthetic":true}';
  const result = await request(`${origin}${CLERK_PROXY_PATH}/v1/client?name=a%2Fb`, 'POST', {
    'content-type': 'application/json',
    cookie: 'session=synthetic',
    'x-forwarded-host': 'public.example.test, internal.test',
    'x-forwarded-proto': 'https',
    'x-forwarded-for': '198.51.100.20, 192.0.2.10',
    'clerk-proxy-url': 'https://untrusted.example.test',
    'clerk-secret-key': 'untrusted-key',
  }, body);
  assert.equal(received.method, 'POST');
  assert.equal(received.url, '/v1/client?name=a%2Fb');
  assert.equal(received.body, body);
  assert.equal(received.headers?.host, new URL(target).host);
  assert.equal(received.headers?.cookie, 'session=synthetic');
  assert.equal(received.headers?.['clerk-proxy-url'], `https://public.example.test${CLERK_PROXY_PATH}`);
  assert.equal(received.headers?.['clerk-secret-key'], 'synthetic-proxy-secret');
  assert.equal(received.headers?.['x-forwarded-for'], '198.51.100.20');
  assert.equal(result.status, 200);
  assert.equal(result.body.toString(), 'chunked response');
  assert.equal(result.headers['content-length'], String(result.body.length));
  assert.equal(result.headers['transfer-encoding'], undefined);
  assert.deepEqual(result.headers['set-cookie'], ['first=synthetic; Path=/', 'second=synthetic; Path=/']);
});

test('Clerk proxy preserves compressed response bytes and encoding', async t => {
  const compressed = gzipSync('synthetic compressed Clerk response');
  const { origin } = await fixture(t, (_req, res) => {
    res.setHeader('content-encoding', 'gzip');
    res.write(compressed.subarray(0, 8));
    res.end(compressed.subarray(8));
  });
  const result = await request(`${origin}${CLERK_PROXY_PATH}/v1/environment`);
  assert.deepEqual(result.body, compressed);
  assert.equal(result.headers['content-encoding'], 'gzip');
  assert.equal(result.headers['content-length'], String(compressed.length));
  assert.equal(result.headers['transfer-encoding'], undefined);
});

for (const scenario of [{ method: 'GET', status: 204 }, { method: 'HEAD', status: 200 }, { method: 'GET', status: 304 }]) {
  test(`Clerk proxy handles bodyless ${scenario.method}/${scenario.status} responses`, async t => {
    const { origin } = await fixture(t, (_req, res) => {
      res.statusCode = scenario.status;
      if (scenario.status !== 204) res.setHeader('content-length', '123');
      res.end();
    });
    const result = await request(`${origin}${CLERK_PROXY_PATH}/v1/client`, scenario.method);
    assert.equal(result.status, scenario.status);
    assert.equal(result.body.length, 0);
    assert.equal(result.headers['transfer-encoding'], undefined);
    assert.equal(result.headers['content-length'], scenario.status === 204 ? undefined : '123');
  });
}

test('Clerk proxy streams length-known responses unchanged', async t => {
  const { origin } = await fixture(t, (_req, res) => {
    res.setHeader('content-length', '7');
    res.end('fixture');
  });
  const result = await request(`${origin}${CLERK_PROXY_PATH}/npm/asset.js`);
  assert.equal(result.body.toString(), 'fixture');
  assert.equal(result.headers['content-length'], '7');
});

test('Clerk proxy fails closed without exposing upstream errors or credentials', async t => {
  const { origin } = await fixture(t, req => req.socket.destroy());
  const result = await request(`${origin}${CLERK_PROXY_PATH}/v1/client`);
  assert.equal(result.status, 502);
  assert.equal(result.body.length, 0);
  assert.equal(result.headers['content-length'], '0');
});

test('Clerk proxy aborts a truncated response rather than hanging or crashing', async t => {
  const { origin } = await fixture(t, (_req, res) => {
    res.writeHead(200, { 'content-length': '100' });
    res.write('partial');
    setTimeout(() => res.destroy(), 20);
  });
  await assert.rejects(request(`${origin}${CLERK_PROXY_PATH}/npm/asset.js`), /aborted|socket hang up|ECONNRESET/);
});

for (const environment of ['development', 'production']) {
  test(`Clerk proxy bypasses safely without ${environment === 'production' ? 'a configured secret' : 'production mode'}`, async t => {
    let calls = 0;
    const { origin } = await fixture(t, (_req, res) => { calls++; res.end(); }, environment, environment === 'production' ? '' : 'synthetic-proxy-secret');
    assert.equal((await request(`${origin}${CLERK_PROXY_PATH}/v1/client`)).status, 418);
    assert.equal(calls, 0);
  });
}
