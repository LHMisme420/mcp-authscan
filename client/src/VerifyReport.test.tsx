import assert from 'node:assert/strict';
import { test } from 'node:test';
import { renderToStaticMarkup } from 'react-dom/server';
import { createRequire } from 'node:module';
import { build } from 'esbuild';
import React from 'react';

test('public verifier offers JSON input without target, login or payment gates', async () => {
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
  const html = renderToStaticMarkup(React.createElement(module.exports.default));
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
  assert.match(html, /Schema-3 reports using verdict-v3, plus the pre-schema-3 format written by releases 1.1.21 to 1.1.24/);
  assert.match(html, /marked LEGACY; it was never signed, so it always shows NOT SIGNED/);
  assert.doesNotMatch(html, /name="target"|type="password"/);
});
