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
  assert.match(html, /someone who changes the content can also recompute/);
  assert.match(html, /Schema-3 reports using verdict-v3 only/);
  assert.doesNotMatch(html, /name="target"|type="password"/);
});
