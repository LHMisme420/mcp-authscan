import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { JSDOM } from 'jsdom';
import { sendFrontendPage } from '../server/publicPages';

test('fetched production homepage HTML contains the three native closing anchors before JavaScript', async t => {
  const app = express();
  app.get(['/', '/assessment', '/scope', '/sample-report'], sendFrontendPage);
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const response = await fetch(`${origin}/`);
  assert.equal(response.status, 200);
  const html = await response.text();
  // Parse the actual response without loading any scripts.
  const document = new JSDOM(html).window.document;
  const closing = document.querySelector('.scope-closing-block')!;
  assert(closing);
  const anchors = [...closing.querySelectorAll('a')];
  assert.equal(anchors.length, 3);
  assert.deepEqual(anchors.map(anchor => anchor.textContent), [
    'Start a scope request', 'See a sample report', 'Email Leroy',
  ]);
  assert.equal(anchors[0].getAttribute('href'), '/scope');
  assert.equal(anchors[1].getAttribute('href'), '/sample-report');
  assert.equal(new URL(anchors[2].getAttribute('href')!).pathname, 'lhmisme2011@gmail.com');
  assert.equal(new URL(anchors[2].getAttribute('href')!).protocol, 'mailto:');
  for (const anchor of anchors) assert(!anchor.hasAttribute('onclick'));
  assert.equal(closing.querySelectorAll('button').length, 0);
  assert(document.querySelector('.pricing-tier-grid')!.compareDocumentPosition(closing) & 4);
  assert(closing.compareDocumentPosition(document.querySelector('#report-method')!) & 4);
  const hero = document.querySelector('.hero-copy')!;
  const text = hero.textContent || '';
  assert.equal(text.split('Scope and written authorization are agreed by email before anything is tested.').length - 1, 1);
  assert.equal(text.split('Do not include credentials, tokens or secrets in email.').length - 1, 1);
  assert.equal(text.split('A report may support a buyer review; acceptance is up to the buyer.').length - 1, 1);
  assert(!text.includes('Scope and written authorization are agreed before testing.'));
  assert(!text.includes('No credentials, tokens, passwords, or other secrets in email.'));
  assert.equal(document.querySelectorAll('.pricing-tier').length, 2);
  assert.match(text, /1750 dollars/);
  assert.match(text, /3500 dollars/);
  // Only "/" gets new HTML. Other pages retain the existing SPA template.
  for (const route of ['/assessment', '/scope', '/sample-report']) {
    const other = await fetch(`${origin}${route}`);
    assert.equal(other.status, 200);
    const otherDocument = new JSDOM(await other.text()).window.document;
    assert.equal(otherDocument.querySelector('#root')!.innerHTML, '');
  }
});
