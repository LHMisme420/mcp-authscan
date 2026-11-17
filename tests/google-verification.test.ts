import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { publicDocuments } from '../server/publicPages';

test('Google verification is served publicly at the site root and supplied property prefix', async t => {
  const app = express();
  app.use(publicDocuments);
  app.use((_req, res) => res.status(401).send('Account required'));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const expected = 'google-site-verification: google4d11d51a142646af.html';
  for (const route of ['/google4d11d51a142646af.html', '/sitemap.xml/google4d11d51a142646af.html']) {
    const response = await fetch(`${origin}${route}`, { redirect: 'manual' });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') || '', /text\/html/);
    assert.equal(await response.text(), expected);
    assert.equal((await fetch(`${origin}${route}`, { method: 'HEAD' })).status, 200);
  }
  const sitemap = await fetch(`${origin}/sitemap.xml`);
  assert.equal(sitemap.status, 200);
  assert.match(sitemap.headers.get('content-type') || '', /(?:application|text)\/xml/);
  assert.equal(await sitemap.text(), await readFile('client/public/sitemap.xml', 'utf8'));
  assert.equal((await fetch(`${origin}/google-other-file.html`)).status, 401);
  assert.equal((await fetch(`${origin}/google4d11d51a142646af.html`, { method: 'POST' })).status, 401);
  assert.equal(await readFile('build/client/google4d11d51a142646af.html', 'utf8'), expected);
});
