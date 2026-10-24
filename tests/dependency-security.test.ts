import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

const require = createRequire(import.meta.url);

test('locked download URLs stay portable HTTPS URLs rather than workspace-only registry addresses', () => {
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  for (const [name, entry] of Object.entries(lock.packages)) {
    const resolved = (entry as { resolved?: string }).resolved;
    if (!resolved) continue;
    const download = new URL(resolved);
    assert.equal(download.protocol, 'https:', `Non-HTTPS download for ${name}`);
    assert.notEqual(download.hostname, 'package-firewall.replit.internal', `Workspace-only download for ${name}`);
  }
});

test('resolved dependency graph contains no vulnerable braces or old uuid', () => {
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  const packages = Object.entries(lock.packages) as [string, { version?: string }][];
  assert.equal(packages.some(([name]) => name.endsWith('/braces')), false);
  assert.equal(packages.some(([name]) => name.endsWith('/http-proxy-middleware')), false);
  const uuidEntries = packages.filter(([name]) => name.endsWith('/uuid'));
  assert.ok(uuidEntries.length > 0);
  for (const [, value] of uuidEntries) {
    const [major, minor, patch] = value.version!.split('.').map(Number);
    assert.ok(major === 11 && (minor > 1 || minor === 1 && patch >= 1), `Expected patched CommonJS-compatible uuid, got ${value.version}`);
  }
});

test('patched uuid retains CommonJS v4 compatibility and rejects truncated v3/v5/v6 output', () => {
  const { v3, v4, v5, v6, validate } = require('uuid');
  assert.equal(validate(v4()), true);
  const namespace = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
  for (const fn of [
    () => v3('fixture', namespace, new Uint8Array(8), 4),
    () => v5('fixture', namespace, new Uint8Array(8), 4),
    () => v6({}, new Uint8Array(8), 4),
  ]) assert.throws(fn, RangeError);
});

test('all resolved body-parser installations exclude the compressed-body crash vulnerability', () => {
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  const entries = Object.entries(lock.packages).filter(([name]) =>
    name === 'node_modules/body-parser' || name.endsWith('/node_modules/body-parser'));
  assert.ok(entries.length > 0);
  for (const [, entry] of entries) {
    const version = (entry as { version: string }).version;
    const [major, minor] = version.split('.').map(Number);
    assert.ok(major === 2 && minor >= 4, `Expected patched compatible body-parser, got ${version}`);
  }
});

test('compressed JSON and form parsing survive malformed and delayed trailing data', () => {
  // An unhandled decompressor error must fail this child, not crash the test runner.
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import http from 'node:http';
    import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';
    import { setTimeout as delay } from 'node:timers/promises';
    import express from 'express';
    const app = express();
    app.use(express.json({ limit: '32kb' }));
    app.use(express.urlencoded({ extended: true }));
    app.post('/body', (req, res) => res.json(req.body));
    app.get('/health', (_req, res) => res.json({ ok: true }));
    app.use((error, _req, res, _next) => res.status(error.status || 500).end());
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const agent = new http.Agent({ keepAlive: true });
    async function post(body, encoding, contentType = 'application/json', trailing = false) {
      let request;
      const response = new Promise((resolve, reject) => {
        request = http.request({
          host: '127.0.0.1', port: server.address().port, path: '/body',
          method: 'POST', agent,
          headers: { 'Content-Type': contentType, ...(encoding ? { 'Content-Encoding': encoding } : {}) },
        }, res => {
          let text = '';
          res.setEncoding('utf8');
          res.on('data', chunk => text += chunk);
          res.on('end', () => resolve({ status: res.statusCode, text }));
          res.on('error', reject);
        });
        request.on('error', reject);
        request.setTimeout(2000, () => request.destroy(new Error('request timeout')));
      });
      if (trailing) {
        request.write(body);
        await delay(30);
        request.end(Buffer.from('invalid trailing bytes'));
      } else request.end(body);
      return response;
    }
    try {
      const json = Buffer.from(JSON.stringify({ ok: true }));
      for (const [encoding, compress] of [
        ['gzip', gzipSync], ['deflate', deflateSync], ['br', brotliCompressSync],
      ]) {
        const valid = await post(compress(json), encoding);
        assert.equal(valid.status, 200);
        assert.deepEqual(JSON.parse(valid.text), { ok: true });
        for (const contentType of ['application/json', 'application/x-www-form-urlencoded']) {
          const input = contentType === 'application/json' ? json : Buffer.from('ok=yes');
          const tailed = await post(compress(input), encoding, contentType, true);
          assert.ok([200, 400].includes(tailed.status), String(tailed.status));
          await delay(60);
        }
        assert.equal((await post(Buffer.from('not a compressed frame'), encoding)).status, 400);
      }
      const form = await post(Buffer.from('ok=yes'), null, 'application/x-www-form-urlencoded');
      assert.equal(form.status, 200);
      assert.deepEqual(JSON.parse(form.text), { ok: 'yes' });
      const healthy = await fetch('http://127.0.0.1:' + server.address().port + '/health');
      assert.equal(healthy.status, 200);
      console.log('compressed-body-regression-ok');
    } finally {
      agent.destroy();
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  `], { cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 15000 });
  assert.equal(result.status, 0, result.stderr || String(result.error));
  assert.match(result.stdout, /compressed-body-regression-ok/);
});
