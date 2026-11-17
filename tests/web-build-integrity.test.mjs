import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sourceSnapshot, assertSource, assertArtifacts, verifyRelease } from '../scripts/web-build-integrity.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const env = { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C.UTF-8' };
async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'vata-web-integrity-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const release = await verifyRelease(root);
  for (const name of [...Object.keys(release.source.files), ...Object.keys(release.artifacts), 'build/release-manifest.json']) {
    await mkdir(path.dirname(path.join(dir, name)), { recursive: true });
    await copyFile(path.join(root, name), path.join(dir, name));
  }
  return { dir, release };
}

test('verified build records real source, both module graphs, and every emitted artifact', async () => {
  const release = await verifyRelease(root);
  assert.equal(release.source.fingerprint, (await sourceSnapshot(root)).fingerprint);
  assert(release.graphs.frontend.includes('client/src/Assessments.tsx'));
  assert(release.graphs.frontend.includes('client/src/RequestAssessment.tsx'));
  assert(release.graphs.server.includes('server/assessmentInquiry.ts'));
  assert(release.artifacts['build/server/index.js']);
});

test('old or modified staged input fails the independent publish fingerprint before building', async t => {
  const { dir, release } = await fixture(t);
  await writeFile(path.join(dir, 'client/src/Assessments.tsx'), 'export default function OldSite() { return null; }');
  await assert.rejects(assertSource(dir, release.source.fingerprint), /Staged source differs/);
  const result = spawnSync(process.execPath, [path.join(dir, 'scripts/deployment-web.mjs'), release.source.fingerprint], { cwd: tmpdir(), env, encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert(!result.stdout.includes('deployment_source_verified'));
  assert(!result.stdout.includes('npm'));
  // Failed preflight must not delete even generated files before diagnosis.
  assert.equal(await readFile(path.join(dir, 'build/client/index.html'), 'utf8'), await readFile(path.join(root, 'build/client/index.html'), 'utf8'));
});

test('missing route bindings fail even if old source would compile successfully', async t => {
  const { dir } = await fixture(t);
  const app = path.join(dir, 'client/src/App.tsx');
  await writeFile(app, (await readFile(app, 'utf8')).replace('path="/assessments"', 'path="/old-assessments"'));
  await assert.rejects(assertSource(dir), /Missing actual route binding/);
});

test('strings alone cannot substitute for actual compiled assessment and inquiry modules', async t => {
  const { dir, release } = await fixture(t);
  const frontend = { ...release.graphs, frontend: release.graphs.frontend.filter(name => name !== 'client/src/RequestAssessment.tsx') };
  await assert.rejects(assertArtifacts(dir, frontend), /Required module was not compiled/);
  const backend = { ...release.graphs, server: release.graphs.server.filter(name => name !== 'server/assessmentInquiry.ts') };
  await assert.rejects(assertArtifacts(dir, backend), /Required module was not compiled/);
});

test('an old emitted client, old HTML, or unmounted backend cannot pass verification', async t => {
  const { dir, release } = await fixture(t);
  const js = Object.keys(release.artifacts).find(name => /^build\/client\/assets\/.*\.js$/.test(name));
  const original = await readFile(path.join(dir, js), 'utf8');
  await writeFile(path.join(dir, js), original.replaceAll('/request-assessment', '/old-request'));
  await assert.rejects(assertArtifacts(dir, release.graphs), /Generated frontend lacks/);
  await writeFile(path.join(dir, js), original);
  const html = path.join(dir, 'build/client/index.html');
  const template = await readFile(html, 'utf8');
  await writeFile(html, template.replaceAll('Independent MCP Security Assessments | MCP AuthScan', 'VATA | MCP Security Workspace'));
  await assert.rejects(assertArtifacts(dir, release.graphs), /old homepage template/);
  await writeFile(html, template);
  const server = path.join(dir, 'build/server/index.js');
  await writeFile(server, (await readFile(server, 'utf8')).replace('app.use("/contact", assessmentInquiryRoutes())', 'app.use("/unmounted", assessmentInquiryRoutes())'));
  await assert.rejects(assertArtifacts(dir, release.graphs), /Generated server lacks/);
});

test('post-verification artifact tampering is rejected even when route markers remain', async t => {
  const { dir, release } = await fixture(t);
  const css = Object.keys(release.artifacts).find(name => name.endsWith('.css'));
  await writeFile(path.join(dir, css), (await readFile(path.join(dir, css), 'utf8')) + '\n/* stale overlay */');
  await assert.rejects(verifyRelease(dir), /Built files changed/);
});

test('a release without the supported email inquiry path cannot pass verification', async t => {
  const { dir, release } = await fixture(t);
  const js = Object.keys(release.artifacts).find(name => /^build\/client\/assets\/.*\.js$/.test(name));
  const original = await readFile(path.join(dir, js), 'utf8');
  for (const marker of [
    'Email us to request an assessment', 'mailto:lhmisme2011@gmail.com',
    encodeURIComponent('Written assessment request — MCP security assessment'),
  ]) {
    await writeFile(path.join(dir, js), original.replaceAll(marker, 'removed-contact-path'));
    await assert.rejects(assertArtifacts(dir, release.graphs), /Generated frontend lacks required content/);
  }
});

test('an old product-first homepage or recurring checkout cannot pass verification', async t => {
  const { dir, release } = await fixture(t);
  const js = Object.keys(release.artifacts).find(name => /^build\/client\/assets\/.*\.js$/.test(name));
  const original = await readFile(path.join(dir, js), 'utf8');
  await writeFile(path.join(dir, js), original.replaceAll('MCP security assessment your buyer', 'Old product-first homepage'));
  await assert.rejects(assertArtifacts(dir, release.graphs), /Generated frontend lacks required content/);
  await writeFile(path.join(dir, js), original + '\n/* https://buy.stripe.com/retired-checkout */');
  await assert.rejects(assertArtifacts(dir, release.graphs), /retired recurring checkout link/);
});

test('missing verification manifest stops npm entry before database or scanner initialization', async t => {
  const { dir } = await fixture(t);
  await rm(path.join(dir, 'build/release-manifest.json'));
  const result = spawnSync(process.execPath, [path.join(dir, 'server/entry.mjs')], {
    cwd: tmpdir(), env: { ...env, DATABASE_URL: 'postgresql://synthetic:synthetic@127.0.0.1:1/synthetic' }, encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /release-manifest/);
  assert(!result.stderr.includes('synthetic:synthetic'));
  assert(!result.stdout.includes('frontend listening'));
});

test('a deployment must receive an explicit fingerprint; there is no ignore-stale flag', async t => {
  const { dir } = await fixture(t);
  const result = spawnSync(process.execPath, [path.join(dir, 'scripts/deployment-web.mjs')], { env, encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /approved web-source fingerprint is required/);
});

test('build resolves its own source/config/output roots from another working directory', { timeout: 60000 }, async t => {
  const { dir } = await fixture(t);
  await symlink(path.join(root, 'node_modules'), path.join(dir, 'node_modules'), 'dir');
  const result = spawnSync(process.execPath, [path.join(dir, 'scripts/build-web.mjs')], {
    cwd: tmpdir(), env, encoding: 'utf8', timeout: 55000,
  });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const release = await verifyRelease(dir);
  assert(release.graphs.frontend.includes('client/src/RequestAssessment.tsx'));
});
