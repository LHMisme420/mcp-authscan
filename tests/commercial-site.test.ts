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
  assert.equal(PUBLIC_SITE_ORIGIN, 'https://mcpauth-scan.com');
  const template = await readFile('client/index.html', 'utf8');
  for (const route of ['/', '/assessment', '/assessments', '/scope', '/request-assessment', '/sample-assessment', '/sample-report', '/sign-in', '/sign-in/sso-callback', '/sign-up', '/user-portal', '/join-team']) {
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
  assert.equal(metadataForPath('/sample-assessment/?campaign=example').canonical, `${PUBLIC_SITE_ORIGIN}/sample-report`);
});

test('public HTML and discovery documents do not require an account or call the private API', async t => {
  const app = express();
  app.use(publicDocuments);
  app.get(['/', '/assessments', '/scope', '/request-assessment', '/sample-assessment', '/sample-report'], sendFrontendPage);
  app.use('/api', (_req, res) => res.status(401).json({ error: 'Unauthorized' }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  t.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  for (const route of ['/', '/assessments', '/scope', '/request-assessment', '/sample-assessment', '/sample-report']) {
    const response = await fetch(`${origin}${route}`);
    assert.equal(response.status, 200);
    const document = new JSDOM(await response.text()).window.document;
    assert.equal(document.title, metadataForPath(route).title);
    assert.equal(response.headers.get('cache-control'), 'no-cache');
  }
  const robots = await fetch(`${origin}/robots.txt`);
  assert.equal(robots.status, 200);
  assert.match(robots.headers.get('content-type') || '', /text\/plain/);
  const robotsText = await robots.text();
  assert.match(robotsText, /^User-agent: \*\nAllow: \//);
  assert.match(robotsText, /Disallow: \/api\//);
  assert.match(robotsText, /Sitemap: https:\/\/mcpauth-scan\.com\/sitemap\.xml/);
  const sitemap = await fetch(`${origin}/sitemap.xml`);
  assert.equal(sitemap.status, 200);
  assert.match(sitemap.headers.get('content-type') || '', /(?:application|text)\/xml/);
  const xml = await sitemap.text();
  const sitemapDocument = new JSDOM(xml, { contentType: 'application/xml' }).window.document;
  assert.deepEqual([...sitemapDocument.querySelectorAll('loc')].map(node => node.textContent), [
    'https://mcpauth-scan.com/', 'https://mcpauth-scan.com/blast-radius',
    'https://mcpauth-scan.com/assessment', 'https://mcpauth-scan.com/assessments',
    'https://mcpauth-scan.com/request-assessment', 'https://mcpauth-scan.com/scope',
    'https://mcpauth-scan.com/sample-report',
  ]);
  assert(!xml.includes('user-portal'));
  assert.equal((await fetch(`${origin}/api/findings`)).status, 401);
});

async function renderComponent(entry: string, path = '/') {
  // Bundle actual components and wouter; only styles are omitted for server
  // rendering. No auth bypass is added to the application or test server.
  const result = await build({
    stdin: {
      contents: `import React from 'react'; import { Router } from 'wouter'; import Component from './${entry}'; export default function Fixture() { return <Router ssrPath="${path}"><Component /></Router>; }`,
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

test('homepage sells named independent assessments without recurring offers or compliance scores', async () => {
  const document = await renderComponent('client/src/Landing.tsx');
  const text = document.body.textContent || '';
  assert.equal(document.querySelector('h1')?.textContent, "MCP security assessment your buyer's review will accept.");
  for (const phrase of ['VATA', 'Leroy H. Mason', 'Independent AI security researcher',
    'credited reporter on published MCP security advisories', 'How the report stands up',
    'MATCH', 'DIVERGENCE', 'NOT REPRODUCIBLE', 'MIT', 'mcp-authscan']) {
    assert(text.includes(phrase), `Missing ${phrase}`);
  }
  assert(!/subscription|monthly|a month|scheduled re.check|scheduled scan|compliance scor|score included|keep checking|\$49/i.test(text));
  assert.equal(document.querySelectorAll('.plan-table, .weekly-plan').length, 0);
  assert.equal(document.querySelector('.pricing-tiers h2')?.textContent, 'Independent MCP security assessments');
  const tierText = Array.from(document.querySelectorAll('.pricing-tier')).map(card => [
    card.querySelector('h3')?.textContent,
    card.querySelector('.pricing-tier-price')?.textContent,
    card.querySelector('p')?.textContent,
  ]);
  assert.deepEqual(tierText, [
    ['Single-server assessment', '1750 dollars', 'One MCP server. Written scope and authorization before testing, evidence-backed findings, and a written report signed by the named researcher. No retest; the full assessment includes one.'],
    ['Full assessment', '3500 dollars', 'A server or fleet, one written report, one retest, and the written scope agreed by email before testing.'],
  ]);
  assert.equal(document.querySelector('.pricing-tiers button')?.textContent, 'Start an assessment');
  assert(!/walkthrough|walk your team|meeting/i.test(text));
  assert.match(text, /hash over the graded content/i);
  assert.match(text, /handshake/i);
  assert.match(text, /authorized tool.call check/i);
  assert(text.indexOf('1750 dollars') < text.indexOf('MIT'), 'Assessment must precede free scanner');
  const links = Array.from(document.querySelectorAll('a'));
  assert(links.some(link => link.href === 'https://pypi.org/project/mcp-authscan/'));
  assert(links.some(link => link.href === 'https://github.com/LHMisme420/mcp-authscan'));
  assert(links.some(link => link.getAttribute('href') === '/sample-report'));
  assert(links.some(link => link.getAttribute('href') === '/sign-in'));
  assert(links.some(link => link.getAttribute('href') === '/sign-up'));
  assert.equal(links.filter(link => /stripe\.com/.test(link.href)).length, 0);
  assert(links.some(link => link.getAttribute('href') === '/assessments'));
  assert(links.some(link => link.getAttribute('href') === '/request-assessment'));
  const emailButton = [...document.querySelectorAll<HTMLAnchorElement>('a.button[href^="mailto:"]')]
    .find(link => link.textContent === 'Email us to request an assessment')!;
  assert(emailButton);
  checkEmailLink(emailButton);
  assert.equal(document.querySelectorAll('form').length, 0);
  for (const anchor of links.filter(link => link.getAttribute('href')?.startsWith('#'))) {
    assert(document.getElementById(anchor.getAttribute('href')!.slice(1)), `Broken anchor ${anchor.href}`);
  }
  const alias = await renderComponent('client/src/Assessment.tsx', '/assessment');
  assert.equal(alias.body.innerHTML, document.body.innerHTML, '/assessment must be a content alias of the homepage');
  const landingSource = await readFile('client/src/Landing.tsx', 'utf8');
  for (const unchangedCopy of [
    'The report carries a hash over the graded content. With written authorization, a second party can re-run the same probe set and compare.',
    'Leroy H. Mason',
    'Independent AI security researcher, credited reporter on published MCP security advisories.',
    'Free, open-source checks',
    'The existing workspace',
    'Run checks. Keep the findings in view.',
  ]) assert(landingSource.includes(unchangedCopy), `Protected landing copy changed or disappeared: ${unchangedCopy}`);
});

test('dedicated assessment details share exact pricing without package-call claims', async () => {
  const document = await renderComponent('client/src/Assessments.tsx');
  const text = document.body.textContent || '';
  for (const phrase of ['Independent MCP security assessments', '1750 dollars', '3500 dollars',
    'Single-server assessment', 'Full assessment',
    'Who signs the report: Leroy H. Mason.',
    'Hash over graded report content', 'MATCH', 'DIVERGENCE', 'NOT REPRODUCIBLE',
    'written authorization', 'available access', 'supported techniques']) {
    assert(text.includes(phrase), `Missing assessment content: ${phrase}`);
  }
  assert.match(text, /MIT-licensed mcp-authscan scanner/);
  assert.equal(document.querySelectorAll('.pricing-tier').length, 2);
  assert.equal(document.querySelectorAll('.pricing-tier a[href^="mailto:"]').length, 0);
  // Checkout is live on this page (owner decision): price and payment sit together,
  // but the scope form comes first so a payment always arrives with a named target.
  const scopeForm = document.querySelector('.written-scope-form-wrap form');
  assert(scopeForm, 'The scope form must be visible on arrival, above checkout');
  assert.equal(document.querySelectorAll('.pricing-start-button').length, 0, 'No toggle: the form is always shown here');
  assert.equal(document.querySelectorAll('.pricing-tier a[href*="stripe.com"]').length, 0, 'No Buy buttons inside the cards, above the form');
  const checkout = document.querySelector('.assessment-checkout')!;
  assert(checkout, 'Checkout section must render on /assessments');
  assert(scopeForm.compareDocumentPosition(checkout) & 4, 'Checkout must follow the scope form');
  assert.deepEqual([...document.querySelectorAll('a[href*="stripe.com"]')].map(a => [a.textContent, a.getAttribute('href')]), [
    ['Pay for the single-server assessment — $1,750', 'https://buy.stripe.com/8x2bJ18pI9tP9Dq64E7Vm01'],
    ['Pay for the full assessment — $3,500', 'https://buy.stripe.com/dRmfZh35o6hDcPCakU7Vm02'],
  ]);
  const next = checkout.textContent || '';
  assert.match(next, /does not start a test/);
  assert.match(next, /agree the written scope and authorization for the server named in the form/);
  assert.match(next, /Nothing is tested until both are agreed in writing/);
  assert(!/subscription|monthly|a month|scheduled re.check|\$49/i.test(text));
  assert(!/walkthrough|walk your team|meeting/i.test(text));
  assert.match(text, /Hash over graded report content/);
});

test('assessment closing links follow the cards before the unchanged report method', async () => {
  const document = await renderComponent('client/src/Landing.tsx');
  const cards = document.querySelector('.pricing-tier-grid')!;
  const primary = document.querySelector<HTMLAnchorElement>('a[href="/scope"]')!;
  const method = document.querySelector('#report-method')!;
  assert(primary, 'The closing primary link must lead to the real scope page');
  assert.equal(primary.textContent, 'Start a scope request');
  assert(cards.compareDocumentPosition(primary) & 4);
  assert(primary.compareDocumentPosition(method) & 4);
  const closing = primary.parentElement!.parentElement!;
  assert.match(closing.textContent || '', /Send the server URL and who authorizes the test/);
  assert.match(closing.textContent || '', /Scope and written authorization are agreed by email before anything is tested/);
  assert.match(closing.textContent || '', /Do not include credentials, tokens or secrets in email/);
  const secondary = [...closing.querySelectorAll('a')].find(link => link.textContent === 'Email Leroy');
  assert(secondary?.getAttribute('href')?.startsWith('mailto:lhmisme2011@gmail.com'));
  const sample = closing.querySelector('a[href="/sample-report"]');
  assert.equal(sample?.textContent, 'See a sample report');
  assert(sample?.classList.contains('secondary'));
  assert.equal(document.querySelector('.public-site-nav a[href="/sample-report"]')?.textContent, 'Sample report');
});

test('/sample-report preserves observations and digests with two price-labeled checkout links and no form', async () => {
  const document = await renderComponent('client/src/SampleReport.tsx', '/sample-report');
  const report = document.querySelector('#sample-report-text')!;
  assert(report, 'A real report page must render, not a SPA redirect');
  const text = report.textContent || '';
  for (const exact of [
    'SAMPLE ASSESSMENT REPORT',
    'AgentPayStore, redacted',
    'Target: agentpaystore.com/book/mcp',
    'Scanner: a development build of mcp-authscan that reported itself as 1.1.24, probe set 2026.11.16.2, severity calibration 2026.11.07.1',
    'VERDICT HIGH. One finding.',
    'tool-call probe not run.',
    'One probe passed. Fifteen were excluded. Coverage, 1 of 1 testable probe.',
    'Sibling transport and origin parity were excluded on a 404.',
    '5f6dc1c9219129473aa84458901209c973ef5d43a564c29976e3efd34eebeaa0',
    'd66a10a3c4d4e66a041476f3598920092a915a34c33c61083609440c1242d607',
    'This server has not been retested.',
  ]) assert(text.includes(exact), `Supplied report changed: ${exact}`);
  assert.equal(document.querySelectorAll('form, input, textarea').length, 0);
  const checkout = [...report.querySelectorAll('.hero-ctas a')];
  assert.deepEqual(checkout.map(a => [a.textContent, a.getAttribute('href')]), [
    ['Single-server assessment — $1,750', 'https://buy.stripe.com/8x2bJ18pI9tP9Dq64E7Vm01'],
    ['Full assessment — $3,500', 'https://buy.stripe.com/dRmfZh35o6hDcPCakU7Vm02'],
  ]);
  assert.equal(report.querySelector('a[href="/scope"]'), null);
  const app = await readFile('client/src/App.tsx', 'utf8');
  assert(app.includes('path="/sample-report" component={SampleReport}'));
  assert(app.includes('path="/sample-assessment"><Redirect to="/sample-report"'));
  assert(!text.includes('Show more'));
});

test('/scope renders its short mailto scope request on arrival without replacing other intake routes', async () => {
  // Since c22e439 /scope has its own five-field request (the full WrittenScopeForm,
  // with the ownership attestation and publish-permission questions, stays on the
  // homepage and /assessments). Authorization is still asked here and still agreed
  // in writing by email before any test.
  const document = await renderComponent('client/src/Scope.tsx', '/scope');
  const form = document.querySelector('form')!;
  assert(form, 'The scope form must already be visible on arrival');
  assert.deepEqual([...form.querySelectorAll('label')].map(label => label.textContent?.replace(/\s+/g, ' ').trim()), [
    'MCP server URL',
    'Name',
    'Email',
    'Who authorizes the test',
    'What the buyer needs the report to prove (optional)',
  ]);
  const required = (id: string) => form.querySelector<HTMLInputElement>(`#${id}`)?.required;
  for (const id of ['request-endpoint', 'request-name', 'request-email', 'request-authority']) assert.equal(required(id), true, `${id} must be required`);
  assert.equal(required('request-buyer-needs'), false);
  assert.equal(form.querySelector<HTMLInputElement>('#request-endpoint')?.type, 'url');
  assert.match(document.body.textContent || '', /Scope and written authorization are agreed by email before anything is tested/);
  assert(!/\b(true|false)\b/.test(form.textContent || ''), 'Visitors must not see raw booleans');
  assert.equal(form.querySelectorAll('button[type="submit"], input[type="submit"]').length, 0, 'Nothing is submitted from this site');
  const send = [...form.querySelectorAll('a.button')].find(a => a.textContent === 'Email scope request');
  assert.match(send?.getAttribute('href') || '', /^mailto:lhmisme2011@gmail.com/);
  assert.match(form.textContent || '', /nothing is sent from this site/);
  const app = await readFile('client/src/App.tsx', 'utf8');
  assert(app.includes('path="/scope" component={Scope}'));
  assert(app.includes('path="/request-assessment" component={RequestAssessment}'));
  assert(app.includes('path="/assessment" component={Assessment}'));
  assert.equal(metadataForPath('/scope').canonical, 'https://mcpauth-scan.com/scope');
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
  assert(document.querySelector('a[href="/sample-report"]'));
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

test('owner-approved sample report wording is frozen, including counts, hashes and limitations', async () => {
  // This is a copy lock, NOT verification of the report's evidence hash.
  // Never update this fixture for tone: obtain the owner's review first.
  const document = await renderComponent('client/src/SampleReport.tsx', '/sample-report');
  const actual = [...document.querySelector('#sample-report-text')!.children].map(node => node.textContent!.trim());
  const approved = (await readFile('tests/fixtures/sample-report.approved.txt', 'utf8')).trim().split('\n');
  assert.deepEqual(actual, approved, 'Sample report wording changed without an approved copy update');
});

test('the synthetic report is retired everywhere in the public frontend', async () => {
  for (const entry of ['Landing', 'Assessments', 'Assessment', 'RequestAssessment', 'SampleReport', 'Scope']) {
    const document = await renderComponent(`client/src/${entry}.tsx`);
    assert(!/synthetic|illustrative|demonstration/i.test(document.body.textContent || ''), `Retired sample copy remains on ${entry}`);
    assert.equal(document.querySelectorAll('a[href="/sample-assessment"]').length, 0);
    assert(document.querySelector('.public-site-nav a[href="/sample-report"]'));
  }
  const app = await readFile('client/src/App.tsx', 'utf8');
  assert(!app.includes("import SampleAssessment"));
  const server = await readFile('server/index.ts', 'utf8');
  assert(server.includes("app.get(['/sample-assessment', '/sample-assessment/'], (_req, res) => res.redirect(301, '/sample-report'))"));
});
