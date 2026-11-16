import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { build } from 'esbuild';
import { metadataForPath, PUBLIC_SITE_ORIGIN } from '../../shared/siteMetadata';
import { JSDOM } from 'jsdom';

async function renderPage(entry: string, path: string) {
  const result = await build({
    stdin: {
      contents: `import React from 'react'; import { Router } from 'wouter'; import Page from './${entry}'; export default function Fixture() { return <Router ssrPath="${path}"><Page /></Router>; }`,
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

test('/assessment is the same public landing content as / with matching offer metadata', async () => {
  const home = await renderPage('client/src/Landing', '/');
  const alias = await renderPage('client/src/Assessment', '/assessment');
  const homePricing = home.querySelector('.pricing-tiers');
  const aliasPricing = alias.querySelector('.pricing-tiers');
  assert(homePricing);
  assert(aliasPricing);
  assert.equal(alias.body.innerHTML, home.body.innerHTML, 'Assessment.tsx must render the same Landing component');
  assert.equal(homePricing.querySelector('h2')?.textContent, 'Independent MCP security assessments');

  const expectedTiers = [
    [
      'Single-server assessment',
      '1750 dollars',
      'One MCP server or a small set of endpoints. Written scope and authorization before testing, evidence-backed findings, a written report signed by the named researcher, and one retest of the same endpoint after fixes.',
    ],
    [
      'Full assessment',
      '3500 dollars',
      'A server or fleet, one written report, one retest, and a written scope agreed before testing.',
    ],
  ];
  const cards = Array.from(alias.querySelectorAll('.pricing-tier'));
  assert.equal(cards.length, 2);
  cards.forEach((card, index) => {
    assert.equal(card.querySelector('h3')?.textContent, expectedTiers[index][0]);
    assert.equal(card.querySelector('.pricing-tier-price')?.textContent, expectedTiers[index][1]);
    assert.equal(card.querySelector('p')?.textContent, expectedTiers[index][2]);
  });
  assert.equal(
    alias.querySelector('.pricing-tiers button')?.textContent,
    'Start an assessment',
  );
  assert(!/walkthrough|walk your team|meeting/i.test(alias.body.textContent || ''));
  assert(!/private assessment.*3,500|Option one|Option two/i.test(alias.body.textContent || ''));

  const metadata = metadataForPath('/assessment');
  const rootMetadata = metadataForPath('/');
  assert.equal(metadata.title, rootMetadata.title);
  assert.equal(metadata.description, rootMetadata.description);
  assert.equal(metadata.canonical, `${PUBLIC_SITE_ORIGIN}/assessment`);
  assert.equal(metadata.robots, 'index, follow');
});
