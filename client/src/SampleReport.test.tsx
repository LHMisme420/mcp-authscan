import assert from 'node:assert/strict';
import { test } from 'node:test';
import { renderToStaticMarkup } from 'react-dom/server';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';
import React from 'react';

async function render() {
  const bundle = await build({
    stdin: {
      contents: `import React from 'react'; import {Router} from 'wouter'; import Page from './client/src/SampleReport'; export default function Fixture(){return <Router ssrPath="/sample-report"><Page /></Router>;}`,
      resolveDir: process.cwd(), loader: 'tsx',
    },
    bundle: true, write: false, platform: 'node', format: 'cjs', jsx: 'automatic',
    loader: { '.css': 'empty' },
    external: ['react', 'react/jsx-runtime', 'react-dom', 'react-dom/server'],
  });
  const module = { exports: {} as { default: React.ComponentType } };
  new Function('require', 'module', 'exports', bundle.outputFiles[0].text)(createRequire(import.meta.url), module, module.exports);
  return renderToStaticMarkup(React.createElement(module.exports.default));
}

const unescape = (s: string) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&amp;/g, '&');

test('AgentPayStore sample is labelled a development build with an unreleased probe set', async () => {
  const html = await render();
  assert.match(html, /a development build of mcp-authscan that reported itself as 1\.1\.24, probe set 2026\.11\.16\.2/);
  assert.match(html, /no published version of mcp-authscan ships probe set 2026\.11\.16\.2/);
  assert.match(html, /e08ed15790a437ed93573757e377f153aedd043a430cf1e3de93ddea514063e5/);   // hash kept as recorded
});

test('reproducible sample names a published release, its wheel hash and the expected report hash', async () => {
  const html = await render();
  const section = html.slice(html.indexOf('id="reproducible-sample"'));
  assert.match(section, /mcp-authscan 1\.1\.26, probe set 2026\.11\.19\.3/);
  assert.match(section, /b67e59bc4bffa9291d66f20657e471308db5d3cf325a0dad95ebc6234989e7cf/);
  assert.match(section, /f679fc77bc27f73836c147cefe7efa8fcf3f0e763c1292f179fdf40c244d2028/);
  const blocks = [...section.matchAll(/<pre><code>([\s\S]*?)<\/code><\/pre>/g)].map((m) => unescape(m[1]));
  assert.equal(blocks.length, 7);
  assert.match(section, /SIGNED BY followed by your key id/);
  // The fixture a reader copies must be valid Python as rendered (catches JSX escaping mistakes).
  const dir = process.env.SAMPLE_BLOCKS_DIR || mkdtempSync(join(tmpdir(), 'sample-'));
  blocks.forEach((b, i) => writeFileSync(join(dir, `block${i + 1}.txt`), b + '\n'));
  writeFileSync(join(dir, 'fixture.py'), blocks[1] + '\n');
  execFileSync('python3', ['-c', 'import ast,sys; ast.parse(open(sys.argv[1]).read())', join(dir, 'fixture.py')]);
});
