import assert from 'node:assert/strict';
import { test } from 'node:test';
import { renderToStaticMarkup } from 'react-dom/server';
import { createRequire } from 'node:module';
import { build } from 'esbuild';
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { JSDOM } from 'jsdom';
import express from 'express';
import { readFileSync } from 'node:fs';
import { reportVerificationRoutes } from '../../server/reportVerification';

async function verifierComponent() {
  const bundle = await build({
    stdin: {
      contents: `import React from 'react'; import {Router} from 'wouter'; import Page from './client/src/VerifyReport'; export default function Fixture(){return <Router ssrPath="/verify"><Page/></Router>}`,
      resolveDir: process.cwd(), loader: 'tsx',
    },
    bundle: true, write: false, platform: 'node', format: 'cjs', jsx: 'automatic',
    loader: { '.css': 'empty' },
    external: ['react', 'react/jsx-runtime', 'react-dom', 'react-dom/server'],
  });
  const module = { exports: {} as { default: React.ComponentType } };
  new Function('require', 'module', 'exports', bundle.outputFiles[0].text)(
    createRequire(import.meta.url), module, module.exports,
  );
  return module.exports.default;
}

test('public verifier offers JSON input without target, login or payment gates', async () => {
  const html = renderToStaticMarkup(React.createElement(await verifierComponent()));
  assert.match(html, /Verify a report/);
  assert.match(html, /id="verify-json"/);
  assert.match(html, /type="file"/);
  assert.match(html, /Verify report/);
  assert.match(html, /Two questions, answered separately/);
  assert.match(html, /Integrity\./);
  assert.match(html, /Authenticity\./);
  assert.match(html, /NOT SIGNED/);
  assert.match(html, /does not create them or hold private keys/);
  assert.match(html, /hash alone can be recomputed by anyone/);
  assert.match(html, /Schema-3 reports using verdict-v3 or verdict-v4, plus the pre-schema-3 format written by releases 1.1.21 to 1.1.24/);
  assert.match(html, /id="verify-second-file"/);
  assert.match(html, /Optional second JSON file to compare/);
  assert.match(html, /marked LEGACY; it was never signed, so it always shows NOT SIGNED/);
  assert.doesNotMatch(html, /name="target"|type="password"/);
});

test('the real form verifies each public file separately and explains their scheme difference', async t => {
  const app = express();
  app.use('/api', reportVerificationRoutes());
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const port = (server.address() as { port: number }).port;
  const dom = new JSDOM('<div id="root"></div>', { url: 'https://verify.example/verify' });
  const originals = new Map<string, PropertyDescriptor | undefined>();
  const requests: { url: string; body: unknown; status: number }[] = [];
  const nativeFetch = globalThis.fetch;
  let rejectSecond = false;
  const first = readFileSync('client/public/tollbooth-2026-11-25.json', 'utf8');
  const second = readFileSync('client/public/tollbooth-authority-2026-11-21.json', 'utf8');
  const globals = {
    window: dom.window, document: dom.window.document, IS_REACT_ACT_ENVIRONMENT: true,
    location: dom.window.location, history: dom.window.history,
    addEventListener: dom.window.addEventListener.bind(dom.window),
    removeEventListener: dom.window.removeEventListener.bind(dom.window),
    fetch: async (url: string, init?: RequestInit) => {
      assert.equal(url, '/api/verify');
      const request = { url, body: init?.body, status: 0 };
      requests.push(request);
      const response = rejectSecond && init?.body === second ? new Response('{}', { status: 429 })
        : await nativeFetch(`http://127.0.0.1:${port}${url}`, init);
      request.status = response.status;
      return response;
    },
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
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  });
  const Component = await verifierComponent();
  await act(async () => root.render(React.createElement(Component)));
  const doc = dom.window.document;
  const upload = async (id: string, text: string, name: string, size = Buffer.byteLength(text)) => {
    const input = doc.getElementById(id)!;
    Object.defineProperty(input, 'files', { configurable: true, value: [{ name, size, text: async () => text }] });
    await act(async () => input.dispatchEvent(new dom.window.Event('change', { bubbles: true })));
  };
  const waitFor = async (predicate: () => unknown) => {
    const deadline = Date.now() + 10000;
    while (!predicate()) {
      if (Date.now() >= deadline) assert.fail(`Verifier UI did not settle: ${doc.body.textContent}`);
      await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)); });
    }
  };
  const submit = async () => {
    await act(async () => doc.querySelector('form')!.dispatchEvent(
      new dom.window.Event('submit', { bubbles: true, cancelable: true })));
  };
  await upload('verify-file', first, 'tollbooth-2026-11-25.json');
  await submit();
  await waitFor(() => doc.querySelector('#verify-result-title'));
  assert.equal(requests.length, 1, 'single-file mode still makes exactly one request');
  assert.equal(doc.querySelector('#verify-comparison-title'), null);
  assert.match(doc.querySelector('#verify-authenticity-title')!.parentElement!.textContent!, /SIGNED BY 9b79936f/);

  await upload('verify-second-file', second, 'tollbooth-authority-2026-11-21.json');
  await submit();
  await waitFor(() => doc.querySelector('#verify-comparison-title'));
  assert.deepEqual(requests.slice(1).map(value => value.body), [first, second]);
  assert(requests.every(value => value.status === 200));
  assert.match(doc.querySelector('#verify-authenticity-title')!.parentElement!.textContent!, /SIGNED BY 9b79936f/);
  assert.match(doc.querySelector('#verify-second-authenticity-title')!.parentElement!.textContent!, /SIGNED BY 9b79936f/);
  const comparison = doc.querySelector('.verify-comparison')!.textContent!;
  assert.match(comparison, /Different hash schemes.*verdict-v4.*verdict-v3/);
  assert.match(comparison, /not classified as identical/);
  assert.match(comparison, /2026-11-25T16:42:34\+00:00/);
  assert.match(comparison, /2026-11-21T11:24:20\+00:00/);
  console.log('Tollbooth UI comparison:', doc.querySelector('#verify-comparison-title')!.textContent);

  const changed = JSON.parse(first);
  changed.probes[0].status = 'FAIL';
  await upload('verify-second-file', JSON.stringify(changed), 'changed.json');
  await submit();
  await waitFor(() => doc.querySelector('#verify-comparison-title'));
  assert.match(doc.querySelector('.verify-comparison-table')!.textContent!, /1issuer-identityPASSissuer-identityFAIL/);
  assert.match(doc.querySelector('#verify-second-result-title')!.parentElement!.textContent!, /ALTERED/);

  await upload('verify-second-file', second, 'too-large.json', 1048577);
  assert.match(doc.querySelector('#verify-second-input-error')!.textContent!, /1 MiB/);
  assert.equal((doc.querySelector('button[type=submit]') as HTMLButtonElement).disabled, true);
  rejectSecond = true;
  await upload('verify-second-file', second, 'second.json');
  await submit();
  await waitFor(() => doc.querySelector('#verify-comparison-title'));
  assert.match(doc.querySelector('#verify-comparison-title')!.textContent!, /Comparison unavailable/);
  assert.match(doc.body.textContent!, /File two: The verifier returned HTTP 429/);
  assert(doc.querySelector('#verify-authenticity-title'), 'a failed second request must not hide the first result');
});
