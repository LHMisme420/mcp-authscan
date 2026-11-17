import test from 'node:test';
import assert from 'node:assert/strict';
import React, { act } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createRoot } from 'react-dom/client';
import { JSDOM } from 'jsdom';
import PricingTiers from './PricingTiers';

test('pricing offers two written assessment options with one start action', () => {
  const html = renderToStaticMarkup(React.createElement(PricingTiers, { emailHref: 'mailto:security@example.com' }));
  assert.equal((html.match(/class="pricing-tier /g) || []).length, 2);
  assert.match(html, /Single-server assessment/);
  assert.match(html, /1750 dollars/);
  assert.match(html, /Full assessment/);
  assert.match(html, /3500 dollars/);
  assert.match(html, /A server or fleet, one written report, one retest, and the written scope agreed by email before testing\./);
  assert.doesNotMatch(html, /publication|mandatory call|Email us to request an assessment/);
  assert.match(html, />Start an assessment</);
  assert.doesNotMatch(html, /<a class="text-link"/);
  assert.match(html, /<p>A server or fleet[^<]*<\/p><button class="button pricing-start-button"/);
});

test('Submit opens a fixed-recipient draft with every entered answer and never sends it automatically', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'https://scope.example' });
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const globals: Record<string, unknown> = {
    window: dom.window, document: dom.window.document, FormData: dom.window.FormData,
    IS_REACT_ACT_ENVIRONMENT: true,
  };
  let fetchCalls = 0;
  globals.fetch = () => {
    fetchCalls += 1;
    throw new Error('Fetch must not be used by the mailto form.');
  };
  for (const [key, value] of Object.entries(globals)) {
    originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const root = createRoot(dom.window.document.getElementById('root')!);
  t.after(async () => {
    await act(async () => root.unmount());
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
    dom.window.close();
  });
  await act(async () => root.render(<PricingTiers emailHref="mailto:owner@example.invalid" />));
  assert.equal(dom.window.document.querySelector('form'), null);
  await act(async () => (dom.window.document.querySelector('button') as HTMLButtonElement).click());
  const document = dom.window.document;
  const form = document.querySelector('form')!;
  assert(form);
  assert.equal(form.querySelectorAll('textarea').length, 3);
  assert.equal(form.querySelector('input[name=authorized]')?.hasAttribute('required'), true);
  assert.equal(form.querySelector('textarea[name=buyerContext]')?.hasAttribute('required'), true);
  assert.equal(form.querySelector('input[name=publicationPermission]')?.hasAttribute('required'), false);
  assert(!/calendar|checkout|booking|walkthrough/i.test(form.textContent || ''));
  const publicationCheckbox = form.querySelector<HTMLInputElement>('input[name=publicationPermission]')!;
  assert.equal(publicationCheckbox.parentElement?.textContent?.includes('No'), true);
  await act(async () => publicationCheckbox.click());
  assert.equal(publicationCheckbox.parentElement?.textContent?.includes('Yes'), true, 'publication answer becomes visibly Yes when checked');
  await act(async () => publicationCheckbox.click());
  assert.equal(publicationCheckbox.parentElement?.textContent?.includes('No'), true, 'publication answer returns to No when unchecked');
  const submitButton = form.querySelector<HTMLButtonElement>('button[type=submit]')!;
  const emailLink = form.querySelector<HTMLAnchorElement>('.written-scope-email-fallback a')!;
  const navigations: string[] = [];
  document.addEventListener('click', (event) => {
    if (event.target === emailLink) {
      event.preventDefault();
      navigations.push(emailLink.href);
    }
  });

  await act(async () => submitButton.click());
  assert.equal(navigations.length, 0, 'missing required answers must block draft activation');
  assert.equal(form.querySelector<HTMLInputElement>('input[name=name]')!.checkValidity(), false);

  for (const [name, value] of Object.entries({
    name: 'INTERNAL SYNTHETIC MAILTO TEST',
    email: 'scope-test@example.com',
    company: 'Synthetic Test Company',
    endpoints: 'https://synthetic.example.invalid/mcp',
    authority: 'Synthetic form test only; no endpoint testing is authorized.',
    buyerContext: 'Synthetic procurement review.',
  })) (form.elements.namedItem(name) as HTMLInputElement).value = value;
  await act(async () => submitButton.click());
  assert.equal(navigations.length, 0, 'unchecked authority must block draft activation');
  assert.equal((form.elements.namedItem('authorized') as HTMLInputElement).checked, false);

  const authorityCheckbox = form.elements.namedItem('authorized') as HTMLInputElement;
  await act(async () => authorityCheckbox.click());
  assert.equal(authorityCheckbox.parentElement?.textContent?.includes('Yes'), true, 'authorized answer becomes visibly Yes when checked');
  await act(async () => submitButton.click());
  assert.equal(navigations.length, 1, 'valid Submit must activate the visible mailto anchor');
  const mailto = new URL(navigations[0]);
  assert.equal(mailto.protocol, 'mailto:');
  assert.equal(mailto.pathname, 'lhmisme2011@gmail.com');
  const subject = mailto.searchParams.get('subject') || '';
  const body = mailto.searchParams.get('body') || '';
  assert.match(subject, /assessment request/i);
  for (const answer of [
    'Your name: INTERNAL SYNTHETIC MAILTO TEST',
    'Work email: scope-test@example.com',
    'Company: Synthetic Test Company',
    'MCP endpoint or URL: https://synthetic.example.invalid/mcp',
    'Who authorizes the test and on what basis: Synthetic form test only; no endpoint testing is authorized.',
    'What buyer or review is waiting on it: Synthetic procurement review.',
    'Permission to publish a redacted result: No',
    'I confirm authority to approve testing: Yes',
  ]) assert(body.includes(answer), `Draft should contain ${answer}`);
  console.log('Decoded mailto draft:', JSON.stringify({ to: mailto.pathname, subject, body }, null, 2));
  assert.match(document.querySelector('[role=status]')!.textContent!, /draft.*not been sent.*press Send/i);
  assert.equal(document.querySelector('form'), form, 'the form remains available after opening the draft');
  assert.equal((form.elements.namedItem('name') as HTMLInputElement).value, 'INTERNAL SYNTHETIC MAILTO TEST');
  assert.equal((form.elements.namedItem('email') as HTMLInputElement).value, 'scope-test@example.com');
  assert.equal((form.elements.namedItem('company') as HTMLInputElement).value, 'Synthetic Test Company');
  assert.equal((form.elements.namedItem('endpoints') as HTMLTextAreaElement).value, 'https://synthetic.example.invalid/mcp');
  assert.equal((form.elements.namedItem('authority') as HTMLTextAreaElement).value, 'Synthetic form test only; no endpoint testing is authorized.');
  assert.equal((form.elements.namedItem('buyerContext') as HTMLTextAreaElement).value, 'Synthetic procurement review.');
  assert.equal((form.elements.namedItem('publicationPermission') as HTMLInputElement).checked, false);
  assert.equal((form.elements.namedItem('authorized') as HTMLInputElement).checked, true);
  assert.equal(fetchCalls, 0);
});

test('the direct fallback URI-encodes special characters and the current checkbox answers', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'https://scope.example' });
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const globals: Record<string, unknown> = {
    window: dom.window, document: dom.window.document, FormData: dom.window.FormData,
    IS_REACT_ACT_ENVIRONMENT: true,
  };
  for (const [key, value] of Object.entries(globals)) {
    originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const root = createRoot(dom.window.document.getElementById('root')!);
  t.after(async () => {
    await act(async () => root.unmount());
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
    dom.window.close();
  });
  await act(async () => root.render(<PricingTiers emailHref="mailto:ignored@example.invalid" />));
  const document = dom.window.document;
  await act(async () => document.querySelector<HTMLButtonElement>('.pricing-start-button')!.click());
  const form = document.querySelector<HTMLFormElement>('form')!;
  for (const [name, value] of Object.entries({
    name: 'A & B "Review"',
    email: 'special+chars@example.invalid',
    company: 'Research, Inc. <Synthetic>',
    endpoints: 'https://synthetic.example.invalid/mcp?q=a&next=%2Fone#part',
    authority: "Written approval: owner's scope & limits?",
    buyerContext: 'Reviewers <team> & procurement',
  })) (form.elements.namedItem(name) as HTMLInputElement).value = value;
  (form.elements.namedItem('authorized') as HTMLInputElement).checked = true;
  (form.elements.namedItem('publicationPermission') as HTMLInputElement).checked = false;
  const fallback = document.querySelector<HTMLAnchorElement>('.written-scope-email-fallback a')!;
  const navigations: string[] = [];
  document.addEventListener('click', (event) => {
    if (event.target === fallback) {
      event.preventDefault();
      navigations.push(fallback.href);
    }
  });
  await act(async () => fallback.click());
  assert.equal(navigations.length, 1);
  const mailto = new URL(navigations[0]);
  assert.equal(mailto.protocol, 'mailto:');
  assert.equal(mailto.pathname, 'lhmisme2011@gmail.com');
  const encodedHref = navigations[0];
  assert.match(encodedHref, /%26|%3C|%3E|%3F|%23/);
  const body = mailto.searchParams.get('body') || '';
  for (const exactAnswer of [
    'Your name: A & B "Review"',
    'Company: Research, Inc. <Synthetic>',
    'MCP endpoint or URL: https://synthetic.example.invalid/mcp?q=a&next=%2Fone#part',
    "Who authorizes the test and on what basis: Written approval: owner's scope & limits?",
    'What buyer or review is waiting on it: Reviewers <team> & procurement',
    'Permission to publish a redacted result: No',
  ]) assert(body.includes(exactAnswer), `Encoded draft should preserve ${exactAnswer}`);
  assert.doesNotMatch(body, /calendar|checkout/i);
});

test('homepage, single-server, and full-assessment triggers open the same complete scope form', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'https://scope.example' });
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const globals: Record<string, unknown> = {
    window: dom.window,
    document: dom.window.document,
    FormData: dom.window.FormData,
    IS_REACT_ACT_ENVIRONMENT: true,
  };
  for (const [key, value] of Object.entries(globals)) {
    originals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const root = createRoot(dom.window.document.getElementById('root')!);
  t.after(async () => {
    await act(async () => root.unmount());
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
    dom.window.close();
  });

  await act(async () => root.render(
    <PricingTiers
      emailHref="mailto:owner@example.invalid"
      homepageVariant
      renderLead={(openForm) => <button type="button" onClick={openForm}>Start an assessment</button>}
    />,
  ));
  const document = dom.window.document;
  const buttons = Array.from(document.querySelectorAll('button'));
  assert.equal(buttons.length, 3);
  const verifyCompleteForm = () => {
    const form = document.querySelector('form.written-scope-form');
    assert(form);
    assert.equal(form.querySelectorAll('textarea').length, 3);
    assert.deepEqual(
      Array.from(form.querySelectorAll('input, textarea')).map((field) => field.getAttribute('name')),
      ['name', 'email', 'company', 'endpoints', 'authority', 'buyerContext', 'publicationPermission', 'authorized'],
    );
  };

  await act(async () => buttons[0].click());
  verifyCompleteForm();
  await act(async () => buttons[2].click());
  assert.equal(document.querySelector('form.written-scope-form'), null);
  await act(async () => buttons[1].click());
  verifyCompleteForm();
  await act(async () => buttons[1].click());
  assert.equal(document.querySelector('form.written-scope-form'), null);
  await act(async () => buttons[2].click());
  verifyCompleteForm();
});
