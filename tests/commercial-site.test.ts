import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { JSDOM } from 'jsdom';
import { metadataForPath, PUBLIC_SITE_ORIGIN, renderPageMetadata } from '../shared/siteMetadata';
import { publicDocuments, sendFrontendPage } from '../server/publicPages';

test('public and account routes get honest titles, canonical URLs, and indexing rules', async () => {
  const template = await readFile('client/index.html', 'utf8');
  for (const route of ['/', '/sample-assessment', '/sign-in', '/sign-in/sso-callback', '/sign-up', '/user-portal', '/join-team']) {
    const expected = metadataForPath(route);
    const document = new JSDOM(renderPageMetadata(template, route)).window.document;
    assert.match(document.title, /MCP AuthScan/);
    assert.equal(document.title, expected.title);
    assert.equal(document.querySelector('meta[name="description"]')?.getAttribute('content'), expected.description);
    assert.equal(document.querySelector('meta[name="robots"]')?.getAttribute('content'), expected.robots);
    assert.equal(document.querySelector('link[rel="canonical"]')?.getAttribute('href'), expected.canonical);
    assert.equal(document.querySelector('meta[property="og:url"]')?.getAttribute('content'), expected.canonical);
    assert.equal(document.querySelector('meta[property="og:title"]')?.getAttribute('content'), expected.title);
    assert.equal(document.querySelector('meta[property="og:description"]')?.getAttribute('content'), expected.description);
    assert.equal(document.querySelector('meta[name="twitter:description"]')?.getAttribute('content'), expected.description);
    assert(!expected.canonical.includes('replit.dev'));
  }
  // Price dollar signs must survive HTML template replacement literally.
  assert.match(renderPageMetadata(template, '/'), /\$1,750/);
  assert.equal(metadataForPath('/sample-assessment/?campaign=example').canonical, `${PUBLIC_SITE_ORIGIN}/sample-assessment`);
});

test('public HTML and discovery documents do not require an account or call the private API', async t => {
  const app = express();
  app.use(publicDocuments);
  app.get(['/', '/sample-assessment'], sendFrontendPage);
  app.use('/api', (_req, res) => res.status(401).json({ error: 'Unauthorized' }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  for (const route of ['/', '/sample-assessment']) {
    const response = await fetch(`${origin}${route}`);
    assert.equal(response.status, 200);
    const document = new JSDOM(await response.text()).window.document;
    assert.equal(document.title, metadataForPath(route).title);
    assert.equal(response.headers.get('cache-control'), 'no-cache');
  }
  const robots = await fetch(`${origin}/robots.txt`);
  assert.equal(robots.status, 200);
  assert.match(await robots.text(), /Disallow: \/api\//);
  const sitemap = await fetch(`${origin}/sitemap.xml`);
  assert.equal(sitemap.status, 200);
  const xml = await sitemap.text();
  assert.match(xml, /sample-assessment/);
  assert(!xml.includes('user-portal'));
  assert.equal((await fetch(`${origin}/api/findings`)).status, 401);
});

async function renderComponent(entry: string) {
  // Bundle actual components and wouter; only styles are omitted for server
  // rendering. No auth bypass is added to the application or test server.
  const result = await build({
    stdin: {
      contents: `import React from 'react'; import { Router } from 'wouter'; import Component from './${entry}'; export default function Fixture() { return <Router ssrPath="/"><Component /></Router>; }`,
      resolveDir: process.cwd(), sourcefile: 'commercial-test-fixture.tsx', loader: 'tsx',
    },
    bundle: true, write: false, platform: 'node',
    format: 'cjs', jsx: 'automatic', loader: { '.css': 'empty' },
    external: ['react', 'react/jsx-runtime', 'react-dom', 'react-dom/server'],
  });
  const module = { exports: {} as { default: React.ComponentType } };
  new Function('require', 'module', 'exports', result.outputFiles[0].text)(
    createRequire(import.meta.url), module, module.exports,
  );
  return new JSDOM(renderToStaticMarkup(React.createElement(module.exports.default))).window.document;
}

test('homepage sells independent assessments while preserving the scanner workspace and existing recurring offer', async () => {
  const document = await renderComponent('client/src/Landing.tsx');
  const text = document.body.textContent || '';
  assert.match(document.querySelector('h1')?.textContent || '', /independent|assessment/i);
  for (const phrase of ['$1,750', '$3,500', 'Single-server', 'Expanded', '$49 a month', 'Coordinate', 'Investigate', 'Weekly re-checks']) {
    assert(text.includes(phrase), `Missing ${phrase}`);
  }
  assert.match(text, /one.*retest/i);
  assert.match(text, /free/i);
  assert.match(text, /written.*authoriz|written.*permission/i);
  for (const verdict of ['PASS', 'FAIL', 'NOT_OBSERVED', 'EXCLUDED']) assert(text.includes(verdict));
  const links = Array.from(document.querySelectorAll('a'));
  assert(links.some(link => link.href === 'https://pypi.org/project/mcp-authscan/'));
  assert(links.some(link => link.href === 'https://github.com/LHMisme420/mcp-authscan'));
  assert(links.some(link => link.getAttribute('href') === '/sample-assessment'));
  assert(links.some(link => link.getAttribute('href') === '/sign-in'));
  assert(links.some(link => link.getAttribute('href') === '/sign-up'));
  const payment = links.find(link => link.href === 'https://buy.stripe.com/aFabJ1dK2axT4j664E7Vm00');
  assert(payment);
  assert.equal(payment.target, '_blank');
  assert(payment.rel.includes('noopener'));
  assert.equal(links.filter(link => /stripe\.com/.test(link.href)).length, 1);
  const contact = links.filter(link => link.getAttribute('href')?.startsWith('mailto:'));
  assert(contact.length > 0);
  for (const link of contact) {
    const url = new URL(link.href);
    assert.equal(url.pathname, 'lhmisme2011@gmail.com');
    assert(!/password|api.?key|token/i.test(url.searchParams.get('body') || ''));
  }
  assert(text.includes('lhmisme2011@gmail.com'));
  assert.equal(document.querySelectorAll('form').length, 0, 'Do not imply a contact submission backend exists');
  for (const anchor of links.filter(link => link.getAttribute('href')?.startsWith('#'))) {
    assert(document.getElementById(anchor.getAttribute('href')!.slice(1)), `Broken anchor ${anchor.href}`);
  }
});

test('public content is not gated on sign-in loading and protected routes retain authorization', async () => {
  const source = await readFile('client/src/App.tsx', 'utf8');
  const home = source.slice(source.indexOf('function HomeRoute()'), source.indexOf('function ProtectedRoute'));
  assert(!home.includes('return <AuthLoading'));
  assert.match(home, /isLoaded && isSignedIn/);
  assert.match(home, /Redirect to="\/user-portal"/);
  assert(source.includes('path="/sign-in/*?"'));
  assert(source.includes('path="/sign-up/*?"'));
  assert(source.includes('<ProtectedRoute>'));
  assert(source.includes("if (isSignedIn) return <>{children}</>"));
  const server = await readFile('server/index.ts', 'utf8');
  assert(server.indexOf("app.get(['/', '/sample-assessment'") < server.indexOf('clerkMiddleware((req)'));
  assert(server.includes("res.status(401).json({ error: 'Unauthorized' })"));
});

test('sample report is clearly synthetic, bounded, and not a customer or scanner coverage claim', async () => {
  const document = await renderComponent('client/src/SampleAssessment.tsx');
  const text = document.body.textContent || '';
  assert.match(text, /synthetic/i);
  assert.match(text, /no.*requests.*sent|no.*target.*contacted/i);
  assert.match(text, /not.*customer|not.*client/i);
  assert.match(text, /mcp\.example\.invalid/);
  for (const phrase of ['PASS', 'FAIL', 'NOT_OBSERVED', 'EXCLUDED', 'Cache-Control', 'no-store', '503', '401']) {
    assert(text.includes(phrase), `Missing sample detail ${phrase}`);
  }
  assert.match(text, /retest/i);
  assert.match(text, /scope/i);
  assert.match(text, /illustrative|illustration/i);
  assert(!text.includes('replace-with-real-sha256'));
  assert(!text.includes('Token-CORS'));
  assert.equal(document.querySelectorAll('form').length, 0);
});
