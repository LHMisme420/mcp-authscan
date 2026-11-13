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

function checkEmailLink(anchor: HTMLAnchorElement, packageLabel?: string) {
  assert.equal(anchor.textContent, 'Email us to request an assessment');
  const href = anchor.getAttribute('href')!;
  assert(href.startsWith('mailto:lhmisme2011@gmail.com?'));
  const params = new URLSearchParams(href.slice(href.indexOf('?') + 1));
  assert.match(params.get('subject') || '', /MCP AuthScan/);
  const body = params.get('body') || '';
  for (const prompt of ['Name / company:', 'Desired package:', 'Target and number of MCP servers:', 'Scope:', 'Timeframe:', 'Authorizing party:']) {
    assert(body.includes(prompt), `Missing email prompt: ${prompt}`);
  }
  assert.match(body, /No credentials, tokens, passwords/);
  if (packageLabel) {
    assert(params.get('subject')?.includes(packageLabel));
    assert(body.includes(`Desired package: ${packageLabel}`));
  }
  assert.equal(params.size, 2, 'Only the fixed subject and body may be prefilled');
  assert(!/[\r\n ]/.test(href), 'Subject and body must be URL encoded');
}

test('public and account routes get honest titles, canonical URLs, and indexing rules', async () => {
  const template = await readFile('client/index.html', 'utf8');
  for (const route of ['/', '/assessments', '/request-assessment', '/sample-assessment', '/sign-in', '/sign-in/sso-callback', '/sign-up', '/user-portal', '/join-team']) {
    const expected = metadataForPath(route);
    const document = new JSDOM(renderPageMetadata(template, route)).window.document;
    assert.match(document.title, /MCP AuthScan|VATA/);
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
  assert.match(renderPageMetadata(template, '/assessments'), /\$1,750/);
  assert.equal(metadataForPath('/sample-assessment/?campaign=example').canonical, `${PUBLIC_SITE_ORIGIN}/sample-assessment`);
});

test('public HTML and discovery documents do not require an account or call the private API', async t => {
  const app = express();
  app.use(publicDocuments);
  app.get(['/', '/assessments', '/request-assessment', '/sample-assessment'], sendFrontendPage);
  app.use('/api', (_req, res) => res.status(401).json({ error: 'Unauthorized' }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  for (const route of ['/', '/assessments', '/request-assessment', '/sample-assessment']) {
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
  assert.match(xml, /request-assessment/);
  assert.match(xml, /\/assessments/);
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

test('homepage preserves VATA product-first messaging, workspace and existing recurring offer', async () => {
  const document = await renderComponent('client/src/Landing.tsx');
  const text = document.body.textContent || '';
  assert.match(document.querySelector('h1')?.textContent || '', /allowed to do/i);
  for (const phrase of ['VATA', 'Need independent MCP security verification?', '$49 a month', 'Coordinate', 'Investigate', 'Weekly re-checks']) {
    assert(text.includes(phrase), `Missing ${phrase}`);
  }
  assert(text.indexOf('Workspace features') < text.indexOf('Need independent MCP security verification?'));
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
  assert(links.some(link => link.getAttribute('href') === '/assessments'));
  assert(links.some(link => link.getAttribute('href') === '/request-assessment'));
  const emailButton = document.querySelector<HTMLAnchorElement>('.service-teaser-actions a.button[href^="mailto:"]')!;
  assert(emailButton);
  checkEmailLink(emailButton);
  assert.equal(document.querySelectorAll('form').length, 0);
  for (const anchor of links.filter(link => link.getAttribute('href')?.startsWith('#'))) {
    assert(document.getElementById(anchor.getAttribute('href')!.slice(1)), `Broken anchor ${anchor.href}`);
  }
});

test('dedicated assessment page has exact packages, limits, evidence methodology and inquiry links', async () => {
  const document = await renderComponent('client/src/Assessments.tsx');
  const text = document.body.textContent || '';
  for (const phrase of ['Independent MCP Security Assessments', '$1,750', '$3,500',
    'MCP Server Security Verification', 'Comprehensive MCP Security Assessment',
    'JSON and SARIF', 'one remediation retest', 'Security evidence, not security theater.',
    'Versioned probe sets', 'Separate severity calibration', 'Reproducibility comparisons',
    'written authorization', 'available credentials', 'supported techniques']) {
    assert(text.includes(phrase), `Missing assessment content: ${phrase}`);
  }
  assert.match(text, /free open-source PyPI scanner/);
  for (const service of ['verification', 'comprehensive']) {
    assert(document.querySelector(`a[href="/request-assessment?package=${service}"]`));
  }
  const packageButtons = document.querySelectorAll<HTMLAnchorElement>('.commercial-offer .button');
  assert.equal(packageButtons.length, 2);
  checkEmailLink(packageButtons[0], 'MCP Server Security Verification');
  checkEmailLink(packageButtons[1], 'Comprehensive MCP Security Assessment');
  assert(!document.querySelector('a[href*="stripe.com"]'), 'Assessments are scoped engagements, not automatic checkout');
});

test('inquiry page makes supported email prominent without a misleading submission form', async () => {
  const document = await renderComponent('client/src/RequestAssessment.tsx');
  assert.equal(document.querySelectorAll('form, input, textarea, button[type="submit"]').length, 0);
  const primary = document.querySelector<HTMLAnchorElement>('a.email-primary-cta')!;
  assert(primary);
  checkEmailLink(primary);
  const address = document.querySelector<HTMLAnchorElement>('.email-address-block .contact-mail')!;
  assert.equal(address.textContent, 'lhmisme2011@gmail.com');
  assert.equal(address.getAttribute('href'), 'mailto:lhmisme2011@gmail.com');
  assert(primary.compareDocumentPosition(document.querySelector('.email-template')!) & 4, 'Email CTA must precede the scope template');
  const text = document.body.textContent || '';
  assert.match(text, /not authorization/i);
  assert.match(text, /Online submission is currently unavailable/);
  assert.match(text, /Email is supported/);
  assert.match(text, /select and copy this address into Gmail or another webmail/);
  assert.match(text, /you must review and send it/);
  assert.match(text, /This website submits nothing/);
  assert.match(text, /does not submit or store your inquiry/);
  assert.match(text, /do not send credentials/);
  assert(!text.includes('Resend'));
  const source = await readFile('client/src/RequestAssessment.tsx', 'utf8');
  assert(!source.includes('fetch('), 'Email-only page must not fetch challenges or send inquiries');
  assert(document.querySelector('a[href="/sample-assessment"]'));
});

test('email templates allow only fixed packages and never inject query text or mail headers', async () => {
  const result = await build({
    entryPoints: ['client/src/AssessmentSections.tsx'],
    bundle: true, write: false, platform: 'node', format: 'cjs', jsx: 'automatic',
    external: ['react', 'react/jsx-runtime'],
  });
  const module = { exports: {} as { assessmentEmailFor: (value?: string) => string } };
  new Function('require', 'module', 'exports', result.outputFiles[0].text)(
    createRequire(import.meta.url), module, module.exports,
  );
  const emailFor = module.exports.assessmentEmailFor;
  for (const value of ['__proto__', 'constructor', 'verification\r\nBcc:attacker@example.invalid', 'comprehensive&bcc=attacker@example.invalid', '<script>']) {
    assert.equal(emailFor(value), emailFor('undecided'));
  }
  assert.notEqual(emailFor('verification'), emailFor('comprehensive'));
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
  const publicRoutes = server.indexOf("app.get(['/', '/assessments'");
  assert(publicRoutes >= 0 && publicRoutes < server.indexOf('clerkMiddleware((req)'));
  assert(server.includes("app.use('/contact', assessmentInquiryRoutes())"));
  assert(server.includes("res.status(401).json({ error: 'Unauthorized' })"));
});

test('sample report is clearly synthetic, bounded, and not a customer or scanner coverage claim', async () => {
  const document = await renderComponent('client/src/SampleAssessment.tsx');
  const text = document.body.textContent || '';
  assert.equal(document.querySelector('.synthetic-banner strong')?.textContent, 'Synthetic Demonstration — Not a Real Client Assessment.');
  for (const privateObservation of ['1bcfda42', '2026.11.10.1', '2026.11.07.1']) {
    assert(!text.includes(privateObservation), 'Owner-summary observations must not appear in the synthetic sample');
  }
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
