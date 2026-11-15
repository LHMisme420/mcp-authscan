import assert from 'node:assert/strict';
import { test } from 'node:test';
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { JSDOM } from 'jsdom';
import { checkAuthReadiness } from '../client/src/authReadiness';
import { AuthLoading } from '../client/src/AuthLoading';

test('auth diagnostic preserves actual HTTP status and uses cookies without tokens', async () => {
  let init: RequestInit | undefined;
  const result = await checkAuthReadiness(new AbortController().signal, '/api/__clerk/v1/environment',
    (async (_url, options) => {
      init = options;
      return new Response('{"error":"unavailable"}', { status: 503, headers: { 'content-type': 'application/json' } });
    }) as typeof fetch);
  assert.equal(result.status, 'HTTP 503');
  assert.equal(init?.credentials, 'include');
  assert.equal(init?.cache, 'no-store');
  assert.equal(init?.headers, undefined);
});

test('HTTP 200 remains 200, and HTML fallback is identified rather than treated as auth success', async () => {
  for (const [type, expected] of [
    ['application/json', 'HTTP 200'], ['text/html', 'HTTP 200 — unexpected non-JSON response'],
  ]) {
    const result = await checkAuthReadiness(new AbortController().signal, '/api/__clerk/v1/environment',
      (async () => new Response('{}', { headers: { 'content-type': type } })) as typeof fetch);
    assert.equal(result.status, expected);
  }
});

test('network failures and hung requests never invent an HTTP status', async () => {
  const failed = await checkAuthReadiness(new AbortController().signal, '/auth',
    (async () => { throw new Error('private provider details'); }) as typeof fetch);
  assert.equal(failed.status, 'Network error — no HTTP status received');
  const hung = await checkAuthReadiness(new AbortController().signal, '/auth',
    ((_url, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
    })) as typeof fetch, 5);
  assert.equal(hung.status, 'Timed out — no HTTP status received');
});

test('workspace loading becomes an accessible error with status and recovery links', async () => {
  const dom = new JSDOM('<div id="root"></div>', { url: 'http://localhost/user-portal' });
  const previous = { window: globalThis.window, document: globalThis.document };
  Object.assign(globalThis, { window: dom.window, document: dom.window.document, IS_REACT_ACT_ENVIRONMENT: true });
  const root = createRoot(dom.window.document.getElementById('root')!);
  let checks = 0;
  const check = async () => { checks++; return { request: '/api/__clerk/v1/environment', status: 'HTTP 403' }; };
  try {
    await act(async () => { root.render(<AuthLoading timeoutMs={10} check={check} />); });
    assert.match(dom.window.document.body.textContent!, /Loading secure workspace/);
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 30)); });
    assert.match(dom.window.document.querySelector('[role="alert"]')!.textContent!, /HTTP 403/);
    assert.doesNotMatch(dom.window.document.body.textContent!, /Loading secure workspace…/);
    assert.equal(dom.window.document.querySelector('a')?.getAttribute('href'), '/sign-in?redirect_url=%2Fuser-portal');
    assert.equal(checks, 1);
  } finally {
    await act(async () => root.unmount());
    Object.assign(globalThis, previous);
    dom.window.close();
  }
});
