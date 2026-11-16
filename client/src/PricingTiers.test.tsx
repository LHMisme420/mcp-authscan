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
  assert.match(html, /A server or fleet, one written report, one retest, and a written scope agreed before testing\./);
  assert.doesNotMatch(html, /publication|mandatory call|Email us to request an assessment/);
  assert.match(html, />Start an assessment</);
  assert.doesNotMatch(html, /<a class="text-link"/);
});

test('start opens the required plain form; failed save/email is visible and success confirms written scope only', async t => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'https://scope.example' });
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const globals: Record<string, unknown> = {
    window: dom.window, document: dom.window.document, FormData: dom.window.FormData,
    IS_REACT_ACT_ENVIRONMENT: true,
  };
  let posted: Record<string, unknown> | undefined;
  let accepted = false;
  globals.fetch = async (url: string, init?: RequestInit) => {
    if (url.endsWith('/status')) return Response.json({ available: true, challenge: 'synthetic-challenge' });
    assert.equal(url, '/contact/scope');
    assert.equal(init?.method, 'POST');
    posted = JSON.parse(String(init?.body));
    return accepted
      ? Response.json({ saved: true, emailed: true, reference: 'synthetic-email-id' }, { status: 201 })
      : Response.json({ error: 'Could not save and email the request.' }, { status: 503 });
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
  assert.equal(form.querySelectorAll('input[type=radio]').length, 2);
  assert.equal(form.querySelector('input[name=authorized]')?.hasAttribute('required'), true);
  assert(!/calendar|booking|walkthrough/i.test(form.textContent || ''));
  for (const [name, value] of Object.entries({
    name: 'Synthetic Tester', email: 'test@example.invalid', company: 'Synthetic Co',
    endpoints: 'https://example.invalid/mcp', authority: 'Owner authorized to approve testing',
  })) (form.elements.namedItem(name) as HTMLInputElement).value = value;
  (form.elements.namedItem('authorized') as HTMLInputElement).checked = true;
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 2150)); });
  assert.equal(form.querySelector<HTMLButtonElement>('button[type=submit]')?.disabled, false);
  await act(async () => form.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true })));
  assert.match(document.querySelector('[role=alert]')!.textContent!, /Could not save and email/);
  assert.equal((form.elements.namedItem('company') as HTMLInputElement).value, 'Synthetic Co');
  assert.equal(posted?.authorized, true);
  assert.equal(posted?.service, 'verification');
  assert.equal(posted?.endpoints, 'https://example.invalid/mcp');
  accepted = true;
  await act(async () => form.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true })));
  assert.equal(document.querySelector('form'), null);
  assert.match(document.querySelector('[role=status]')!.textContent!, /written scope will follow; no testing happens until you approve it/);
  assert.match(document.querySelector('[role=status]')!.textContent!, /Invoicing is after the scope is agreed/);
});
