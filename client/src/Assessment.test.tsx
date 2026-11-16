import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { build } from 'esbuild';
import { assessmentDraftUrl, isValidAssessmentHostname } from './assessmentForm';
import { metadataForPath, PUBLIC_SITE_ORIGIN } from '../../shared/siteMetadata';
import { JSDOM } from 'jsdom';

async function renderAssessment() {
  const result = await build({
    stdin: {
      contents: `import React from 'react'; import { Router } from 'wouter'; import Assessment from './client/src/Assessment'; export default function Fixture() { return <Router ssrPath="/assessment"><Assessment /></Router>; }`,
      resolveDir: process.cwd(),
      sourcefile: 'assessment-page-fixture.tsx',
      loader: 'tsx',
    },
    bundle: true,
    write: false,
    platform: 'node',
    format: 'cjs',
    jsx: 'automatic',
    loader: { '.css': 'empty' },
    external: ['react', 'react/jsx-runtime', 'react-dom', 'react-dom/server'],
  });
  const module = { exports: {} as { default: React.ComponentType } };
  new Function('require', 'module', 'exports', result.outputFiles[0].text)(
    createRequire(import.meta.url),
    module,
    module.exports,
  );
  return new JSDOM(renderToStaticMarkup(React.createElement(module.exports.default))).window.document;
}

async function renderInquiryForm() {
  const result = await build({
    stdin: {
      contents: `import React from 'react'; import { Router } from 'wouter'; import { AssessmentInquiry } from './client/src/Assessment'; export default function Fixture() { return <Router ssrPath="/assessment"><AssessmentInquiry selectedOption="publication" /></Router>; }`,
      resolveDir: process.cwd(),
      sourcefile: 'assessment-form-fixture.tsx',
      loader: 'tsx',
    },
    bundle: true,
    write: false,
    platform: 'node',
    format: 'cjs',
    jsx: 'automatic',
    loader: { '.css': 'empty' },
    external: ['react', 'react/jsx-runtime', 'react-dom', 'react-dom/server'],
  });
  const module = { exports: {} as { default: React.ComponentType } };
  new Function('require', 'module', 'exports', result.outputFiles[0].text)(
    createRequire(import.meta.url),
    module,
    module.exports,
  );
  return new JSDOM(renderToStaticMarkup(React.createElement(module.exports.default))).window.document;
}

test('assessment page renders supplied offer terms and accessible required inquiry fields', async () => {
  const document = await renderAssessment();
  const text = document.body.textContent || '';
  assert.equal(document.querySelector('h1')?.textContent, 'An MCP AuthScan assessment');
  assert.equal(document.querySelector('.assessment-buy-heading h2')?.textContent, 'Evidence an enterprise buyer will accept');
  for (const phrase of [
    'An independent assessment of your MCP surface, written for the person holding your contract, not for your engineering team.',
    "Your buyer's security review asks a question",
    'One MCP endpoint, or a small set on the same host.',
    'The report is private to you, and nothing is said publicly about it, ever, unless you ask me to.',
    'You see the redaction before it goes out.',
  ]) assert(text.includes(phrase), `Missing supplied copy: ${phrase}`);

  const buttons = Array.from(document.querySelectorAll('button'));
  assert.equal(buttons.filter(button => button.textContent === 'Start an assessment').length, 2);
  assert.equal(document.querySelectorAll('form').length, 0, 'Form stays inline until an option is selected');
  const metadata = metadataForPath('/assessment');
  assert.equal(metadata.canonical, `${PUBLIC_SITE_ORIGIN}/assessment`);
  assert.equal(metadata.robots, 'index, follow');
});

test('selected package form renders labeled required fields and disclosed manual email path', async () => {
  const document = await renderInquiryForm();
  const form = document.querySelector('form');
  assert(form);
  assert.equal(form.querySelectorAll('input[required]').length, 3);
  assert.equal(form.querySelector('input[name="company"]')?.getAttribute('autocomplete'), 'organization');
  assert.equal(form.querySelector('input[name="hostname"]')?.getAttribute('pattern')?.length! > 0, true);
  assert.equal(form.querySelector('input[name="email"]')?.getAttribute('type'), 'email');
  for (const fieldName of ['company', 'hostname', 'email']) {
    const input: HTMLInputElement = form.querySelector(`input[name="${fieldName}"]`) as HTMLInputElement;
    const label: HTMLLabelElement | null = document.querySelector(`label[for="${input.id}"]`);
    assert(label, `Missing label for ${fieldName}`);
    assert.equal(input.hasAttribute('required'), true);
  }
  assert.match(document.body.textContent || '', /Selected option: Assessment with publication — \$2,500/);
  assert.match(document.body.textContent || '', /Scoped and confirmed by email before a single request is sent/);
  assert.match(document.body.textContent || '', /This website does not send or submit it/);
  assert.match(document.body.textContent || '', /copy the recipient above into Gmail or another webmail service/i);
  assert.match(document.body.textContent || '', /lhmisme2011@gmail\.com/);
  assert(document.querySelector('button.copy-recipient'));
});

test('required form inputs have native validation and the host field rejects URLs', () => {
  for (const validHost of ['api.example.com', 'localhost', 'mcp-gateway.internal', 'a.example.org']) {
    assert.equal(isValidAssessmentHostname(validHost), true, `${validHost} should be a valid hostname`);
  }
  for (const invalidHost of [
    '',
    'https://api.example.com',
    'api.example.com/path',
    'user:secret@api.example.com',
    'api.example.com:8443',
    '-bad.example.com',
    'bad..example.com',
    'api example.com',
  ]) assert.equal(isValidAssessmentHostname(invalidHost), false, `${invalidHost} should not be accepted`);

  const draft = assessmentDraftUrl('publication', 'Example & Co', 'api.example.com', 'contact@example.com');
  assert(draft.startsWith('mailto:lhmisme2011@gmail.com?'));
  const query = new URLSearchParams(draft.slice(draft.indexOf('?') + 1));
  assert.equal(query.size, 2, 'Only fixed subject and encoded message body are included');
  assert.match(query.get('subject') || '', /publication.*\$2,500/i);
  assert.match(query.get('body') || '', /Selected option: Assessment with publication — \$2,500/);
  assert.match(query.get('body') || '', /Company: Example & Co/);
  assert.match(query.get('body') || '', /Endpoint host: api\.example\.com/);
  assert.match(query.get('body') || '', /Contact email: contact@example\.com/);

  const hostile = assessmentDraftUrl('private', 'Company\nBcc: attacker@example.com', 'api.example.com', 'a@example.com');
  assert.equal(new URLSearchParams(hostile.slice(hostile.indexOf('?') + 1)).size, 2);
  assert(hostile.includes(encodeURIComponent('Company\nBcc: attacker@example.com')));
});
