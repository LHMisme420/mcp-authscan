import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import { readFile } from 'node:fs/promises';
import { accountOriginGuard, appOrigin, trustedAppOrigins } from '../server/appOrigin';
import { PUBLIC_SITE_ORIGIN, LEGACY_SITE_ORIGIN, metadataForPath } from '../shared/siteMetadata';

test('production canonical links and exact trusted origins support both owned hosts', async t => {
  const previous = { NODE_ENV: process.env.NODE_ENV, PUBLIC_APP_URL: process.env.PUBLIC_APP_URL };
  process.env.NODE_ENV = 'production';
  process.env.PUBLIC_APP_URL = PUBLIC_SITE_ORIGIN;
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
  assert.equal(appOrigin(), 'https://mcpauth-scan.com');
  assert.deepEqual(trustedAppOrigins(), [PUBLIC_SITE_ORIGIN, LEGACY_SITE_ORIGIN]);
  for (const route of ['/', '/assessments', '/request-assessment', '/sample-assessment', '/user-portal']) {
    assert(metadataForPath(route).canonical.startsWith(`${PUBLIC_SITE_ORIGIN}/`));
  }
  const app = express();
  // Synthetic authentication fixture only. Never mount this in the application.
  app.use((req, res, next) => {
    if (req.get('x-test-auth') !== 'fixture') { res.sendStatus(401); return; }
    next();
  });
  app.use(accountOriginGuard);
  app.all('/operation', (_req, res) => res.sendStatus(204));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/operation`;
  for (const origin of [PUBLIC_SITE_ORIGIN, LEGACY_SITE_ORIGIN, 'https://evil.example']) {
    assert.equal((await fetch(url, { method: 'POST', headers: { Origin: origin } })).status, 401);
  }
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    for (const origin of [PUBLIC_SITE_ORIGIN, LEGACY_SITE_ORIGIN]) {
      assert.equal((await fetch(url, { method, headers: { Origin: origin, 'x-test-auth': 'fixture' } })).status, 204);
    }
    for (const origin of ['https://evil.example', 'null', 'http://mcpauth-scan.com',
      'https://mcpauth-scan.com.evil.example', 'https://www.mcpauth-scan.com',
      'https://mcpauth-scan.com:444', `${PUBLIC_SITE_ORIGIN}/`, `${PUBLIC_SITE_ORIGIN},${LEGACY_SITE_ORIGIN}`]) {
      assert.equal((await fetch(url, { method, headers: { Origin: origin, 'x-test-auth': 'fixture',
        'x-forwarded-host': 'mcpauth-scan.com', Host: 'mcpauth-scan.com' } })).status, 403, origin);
    }
  }
  assert.equal((await fetch(url, { method: 'POST', headers: { 'x-test-auth': 'fixture' } })).status, 204);
  const source = await readFile('server/index.ts', 'utf8');
  assert(source.indexOf("app.use('/api', accountOriginGuard)") > source.indexOf("error: 'Unauthorized'"));
  assert.match(source, /authorizedParties: trustedAppOrigins\(\)/);
  assert(!source.includes('origin: true'));
});
