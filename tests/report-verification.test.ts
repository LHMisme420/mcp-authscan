import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import express from 'express';
import { reportVerificationRoutes, shapeEngineResult } from '../server/reportVerification';
import { reportPublicKeys, type PublishedKey } from '../server/reportAuthenticity';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';

// Every verdict is decided by the Python engine (mcp_authscan.verification). These tests
// check that the route forwards the engine's verdict unchanged and decides nothing itself.

const CATALOG_SHA256 = '3d4a9cece1efc12823a982f909b00202cda2c2410dc055b42e9420dcf0be306c';

// RFC 8032 test 1: public key and signature only. No private key is used.
const vectorKey: PublishedKey = {
  key_id: 'rfc8032-test-only', alg: 'ed25519',
  public_key: Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex').toString('base64url'),
};
const vectorSignature = {
  alg: 'ed25519', key_id: vectorKey.key_id,
  value: Buffer.from('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b', 'hex').toString('base64url'),
};

const report = JSON.parse(execFileSync('python3', ['-c', `
import json
from mcp_authscan.report_verify import compute
p = dict(target="https://synthetic.invalid/mcp", status="completed",
 total_checks=1, findings_count=0, probe_set_version="2026.11.19.3",
 coverage={"tested":1}, severity_counts=dict(CRITICAL=0,HIGH=0,MEDIUM=0,LOW=0,INFO=0),
 findings=[], hash_scheme="verdict-v3", schema_version=3)
p["report_hash"] = compute(p, p["findings"])[0]
print(json.dumps(p))
`], { encoding: 'utf8' }));

/** The engine itself: packaged trust anchor (keys null), or the given keys as the anchor. */
const engine = (payload: object, keys: PublishedKey[] | null = null) => JSON.parse(execFileSync('python3', ['-c', `
import json, sys
from mcp_authscan import verification as v
d = json.load(sys.stdin)
anchor = "packaged" if d["keys"] is None else v.anchor_from_keys(d["keys"])
print(json.dumps(v.verify(json.dumps(d["report"]), anchor=anchor)))
`], { input: JSON.stringify({ report: payload, keys }), encoding: 'utf8' }));

/** Python's canonical signed content for a report (report_verify.signed_content). */
const signedContent = (payload: object) => Buffer.from(execFileSync('python3', ['-c', `
import base64, json, sys
from mcp_authscan.report_verify import signed_content
p = json.load(sys.stdin)
sys.stdout.write(base64.b64encode(signed_content(p, p["findings"])).decode())
`], { input: JSON.stringify(payload), encoding: 'utf8' }), 'base64');

async function withRoute(run: (post: (body: string) => Promise<{ status: number; body: any }>, port: number) => Promise<void>) {
  const app = express();
  app.use('/api', reportVerificationRoutes());
  app.get('/keys.json', reportPublicKeys);
  // Prove no authentication/readiness dependency is needed by the public route.
  app.use((_req, res) => res.status(401).end());
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const { port } = server.address() as { port: number };
  const post = async (body: string) => {
    const response = await fetch(`http://127.0.0.1:${port}/api/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    });
    return { status: response.status, body: await response.json() as any };
  };
  try {
    await run(post, port);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

test('public offline verifier reports the engine verdict and rejects malformed reports', async () => {
  await withRoute(async (post, port) => {
    const intact = await post(JSON.stringify(report));
    assert.equal(intact.status, 200);
    assert.equal(intact.body.integrity.verdict, 'INTACT');
    assert.equal(intact.body.integrity.algorithm, 'SHA-256 / verdict-v3');
    assert.equal(intact.body.integrity.probe_set_version, '2026.11.19.3');
    assert.equal(intact.body.authenticity.verdict, 'NOT SIGNED');
    assert.equal(intact.body.authenticity.key_id, null);
    assert.equal(intact.body.catalog.sha256, CATALOG_SHA256, 'Every site result attests the pinned catalog');
    assert.equal(intact.body.catalog.attestation, 'IN CATALOG');
    assert.equal(intact.body.probe_statuses.verdict, 'NOT VERIFIED');
    assert.equal(intact.body.failed_stage, null);
    assert.equal(intact.body.canonical_bytes, undefined, 'Never return internal report transport');
    const altered = (await post(JSON.stringify({ ...report, target: 'changed' }))).body;
    assert.equal(altered.integrity.verdict, 'ALTERED');
    assert.equal(altered.authenticity.verdict, 'NOT SIGNED');
    assert.equal(altered.failed_stage, 'integrity');
    assert.equal((await post(JSON.stringify({ ...report, started_at: 'ignored' }))).body.integrity.verdict, 'INTACT');
    const unknown = (await post(JSON.stringify({ ...report, signature: vectorSignature }))).body;
    assert.equal(unknown.integrity.verdict, 'INTACT');
    assert.equal(unknown.authenticity.verdict, 'UNKNOWN KEY');
    assert.equal(unknown.authenticity.key_id, vectorKey.key_id);
    const malformedSignature = (await post(JSON.stringify({ ...report, signature: null }))).body;
    assert.equal(malformedSignature.integrity.verdict, 'INTACT');
    assert.equal(malformedSignature.authenticity.verdict, 'UNREADABLE');
    for (const text of ['{', 'null', '[]', '{"x":1,"x":2}', '{"x":NaN}',
      JSON.stringify({ ...report, schema_version: 2 }),
      JSON.stringify({ ...report, report_hash: 'short' }),
      JSON.stringify({ ...report, report_hash: undefined }),
      JSON.stringify({ ...report, findings: null }),
      JSON.stringify({ ...report, findings_count: 1 }),
      JSON.stringify({ ...report, probe_set_version: 'not-a-known-probe-set' })]) {
      const body = (await post(text)).body;
      assert.equal(body.integrity.verdict, 'UNREADABLE', text.slice(0, 60));
      assert.equal(body.authenticity.verdict, 'UNREADABLE', 'Parsing failure is not an unsigned report');
      assert.equal(body.failed_stage, 'format');
    }
    const keys = await fetch(`http://127.0.0.1:${port}/keys.json`);
    assert.equal(keys.status, 200);
    assert.deepEqual(await keys.json(), JSON.parse(readFileSync('client/public/keys.json', 'utf8')),
      'Serve exactly the explicitly configured public identities');
    assert.equal((await post(' '.repeat(1048577))).status, 413);
  });
});

test('the route forwards the engine verdict unchanged for every verdict class', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const ownKeyId = createHash('sha256').update(raw).digest('hex');
  const signed = { ...report, signature: { alg: 'ed25519', key_id: ownKeyId,
    value: sign(null, signedContent(report), privateKey).toString('base64url') } };
  const cases: object[] = [
    report, { ...report, target: 'changed' }, { ...report, probe_set_version: '1.1.0' },
    { ...report, signature: vectorSignature }, { ...report, signature: null }, signed,
    { ...report, sig_version: 9, signature: vectorSignature },
    { ...report, sig_version: 2, signature: vectorSignature },
  ];
  await withRoute(async post => {
    for (const payload of cases) {
      const viaRoute = await post(JSON.stringify(payload));
      const shaped = shapeEngineResult(engine(payload));
      assert.ok(shaped, 'engine output must be well formed');
      assert.equal(viaRoute.status, shaped.status);
      assert.deepEqual(viaRoute.body, shaped.body);
    }
  });
});

test('the published report verifies through the route with the pinned key history; a status flip does not', async () => {
  const text = readFileSync('tests/fixtures/published/tollbooth-baseline.json', 'utf8');
  assert.equal(text, readFileSync('client/public/tollbooth-authority-2026-11-21.json', 'utf8'));
  const published = JSON.parse(text);
  const flipped = structuredClone(published);
  const probe = flipped.probes.find((p: any) => p.name === 'token-cors');
  assert.equal(probe.status, 'NOT_OBSERVED');
  probe.status = 'PASS';
  await withRoute(async post => {
    const ok = (await post(text)).body;
    assert.equal(ok.integrity.verdict, 'INTACT');
    assert.equal(ok.authenticity.verdict, 'SIGNED BY');
    assert.equal(ok.authenticity.key_id, '9b79936f975f9770b3840dbd45f93d2bb23d1bd2cc3d7d81d092e5cd41926e9d');
    assert.equal(ok.probe_statuses.verdict, 'VERIFIED');
    assert.equal(ok.catalog.attestation, 'IN CATALOG');
    const forged = (await post(JSON.stringify(flipped))).body;
    assert.equal(forged.integrity.verdict, 'INTACT', 'report_hash does not cover probe statuses');
    assert.equal(forged.authenticity.verdict, 'SIGNATURE INVALID');
    assert.match(forged.authenticity.reason, /probes/);
    assert.equal(forged.probe_statuses.verdict, 'NOT VERIFIED');
    assert.equal(forged.failed_stage, 'authenticity');
  });
});

test('the route makes no decision of its own', () => {
  const good = engine(report);
  assert.ok(shapeEngineResult(good));
  // Anything that is not a well-formed engine result is refused, never interpreted.
  for (const broken of [null, {}, { ...good, engine: 'other' }, { ...good, failed_stage: 'nope' },
    { ...good, authenticity: { ...good.authenticity, verdict: 'SIGNED' } },
    { ...good, integrity: { ...good.integrity, verdict: 'MATCH' } },
    { ...good, probe_statuses: undefined }]) {
    assert.equal(shapeEngineResult(broken as any), null);
  }
  // A catalog failure is a server fault (503), never a verdict about the upload.
  const catalog = shapeEngineResult({ ...good, failed_stage: 'catalog',
    catalog: { verdict: 'FAILED', reason: 'ValueError: catalog digest mismatch' } });
  assert.equal(catalog?.status, 503);
  // No signature verification code remains in the Node server.
  for (const file of readdirSync('server').filter(name => /\.(ts|mjs|js)$/.test(name))) {
    const source = readFileSync(join('server', file), 'utf8');
    assert.doesNotMatch(source, /verifyAuthenticity|createPublicKey|from 'node:crypto'.*\bverify\b/, file);
  }
});

test('versioned signatures cover the exact reference envelope, not the graded hash alone', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const key: PublishedKey = {
    alg: 'ed25519', key_id: createHash('sha256').update(raw).digest('hex'),
    public_key: raw.toString('base64url'),
  };
  for (const version of [undefined, 1, 2, 3]) {
    const payload: any = { ...report, sig_version: version, started_at: 'excluded timestamp' };
    if (version && version >= 2) {
      payload.evidence = { scheme: 'evidence-binding-v1', states: [
        { access_class: 'anonymous', state_id: 'a'.repeat(64) },
      ] };
    }
    if (version === 3) {
      payload.provenance = { tool_version: 'synthetic', tool_manifest: 'b'.repeat(64) };
      payload.probes = [{ name: 'synthetic é', result: 'excluded' }];
    }
    const projected = JSON.parse(signedContent(report).toString('utf8'));
    const envelope: any = !version || version === 1 ? projected
      : version === 2 ? { sig_version: 2, evidence: payload.evidence, report: projected }
      : { sig_version: 3, evidence: payload.evidence, report: projected,
          probes: payload.probes, provenance: payload.provenance };
    // Independent Python serialization of the specified envelope. No signed_content call.
    const expected = execFileSync('python3', ['-c',
      'import json,sys;sys.stdout.buffer.write(json.dumps(json.load(sys.stdin),sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("utf-8"))'],
      { input: JSON.stringify(envelope) });
    assert.deepEqual(signedContent(payload), expected);
    payload.signature = { alg: 'ed25519', key_id: key.key_id,
      value: sign(null, expected, privateKey).toString('base64url') };
    assert.deepEqual(signedContent(payload), expected, 'Signature field never signs itself');
    const result = engine(payload, [key]);
    assert.equal(result.integrity.verdict, 'INTACT');
    assert.equal(result.authenticity.verdict, 'SIGNED BY');
    assert.equal(result.probe_statuses.verdict, version === 3 ? 'VERIFIED' : 'NOT VERIFIED');
    if (version && version >= 2) {
      const altered = engine({ ...payload, evidence: { ...payload.evidence, states: [] } }, [key]);
      assert.equal(altered.integrity.verdict, 'INTACT', 'Evidence remains outside report_hash');
      assert.equal(altered.authenticity.verdict, 'SIGNATURE INVALID');
    }
    // A valid signature stays independent of the stored report_hash; the failed stage is integrity.
    const rehashed = engine({ ...payload, report_hash: '0'.repeat(64) }, [key]);
    assert.equal(rehashed.integrity.verdict, 'ALTERED');
    assert.equal(rehashed.authenticity.verdict, 'SIGNED BY');
    assert.equal(rehashed.failed_stage, 'integrity');
  }
});

test('demonstrated reconstruction divergence names its component without accusing the signature', () => {
  for (const [payload, component] of [
    [{ ...report, sig_version: 2, evidence: { scheme: 'unknown', states: [] } }, 'evidence'],
    [{ ...report, sig_version: 3, evidence: { scheme: 'evidence-binding-v1', states: [] } }, 'sig_version'],
    [{ ...report, sig_version: 2 }, 'sig_version'],
  ] as const) {
    const result = engine({ ...payload, signature: vectorSignature }, [vectorKey]);
    assert.equal(result.integrity.verdict, 'INTACT');
    assert.equal(result.authenticity.verdict, 'DIVERGENCE');
    assert.match(result.authenticity.reason, new RegExp(component));
  }
  const unsupported = engine({ ...report, sig_version: 9, signature: vectorSignature }, [vectorKey]);
  assert.equal(unsupported.authenticity.verdict, 'UNSUPPORTED FORM', 'An unknown form is unsupported, never forged');
});

test('production registry is embedded in the server and equals the pinned key history', async () => {
  const temporary = mkdtempSync(join(tmpdir(), 'embedded-public-registry-'));
  try {
    const outfile = join(temporary, 'registry.mjs');
    await build({
      entryPoints: ['server/reportAuthenticity.ts'], bundle: true,
      platform: 'node', format: 'esm', outfile,
    });
    const keys = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e',
      'const m = await import("./registry.mjs"); console.log(JSON.stringify(await m.publishedKeys()));'],
    { cwd: temporary, env: { ...process.env, NODE_ENV: 'production' }, encoding: 'utf8' }));
    assert.deepEqual(keys, JSON.parse(readFileSync('client/public/keys.json', 'utf8')).keys);
    const active = JSON.parse(execFileSync('python3', ['-c',
      'import json; from mcp_authscan import verification as v; print(json.dumps(v.published_keys(v.packaged_anchor())))'],
    { encoding: 'utf8' }));
    assert.deepEqual(keys, active.keys, '/keys.json must equal the active keys of the pinned key history');
    const owner = keys.find((key: PublishedKey) =>
      key.key_id === '9b79936f975f9770b3840dbd45f93d2bb23d1bd2cc3d7d81d092e5cd41926e9d');
    assert.ok(owner, 'The owner-approved public key must ship in the build');
    assert.equal(owner.alg, 'ed25519');
    assert.equal(owner.public_key, 'pN7dkDEfe08lCTp2JZDXXyIZeyRQg6aOGF81acN_xw8');
    assert.equal(createHash('sha256').update(Buffer.from(owner.public_key, 'base64url')).digest('hex'),
      owner.key_id);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
