import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import express from 'express';
import { reportVerificationRoutes } from '../server/reportVerification';
import { reportPublicKeys, verifyAuthenticity, type PublishedKey } from '../server/reportAuthenticity';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build } from 'esbuild';

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
 total_checks=1, findings_count=0, probe_set_version="synthetic-test",
 coverage={"tested":1}, severity_counts=dict(CRITICAL=0,HIGH=0,MEDIUM=0,LOW=0,INFO=0),
 findings=[], hash_scheme="verdict-v3", schema_version=3)
p["report_hash"] = compute(p, p["findings"])[0]
print(json.dumps(p))
`], { encoding: 'utf8' }));

test('public offline verifier uses the CLI hash and rejects malformed reports', async () => {
  const app = express();
  app.use('/api', reportVerificationRoutes());
  app.get('/keys.json', reportPublicKeys);
  // Prove no authentication/readiness dependency is needed by the public route.
  app.use((_req, res) => res.status(401).end());
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>(resolve => server.once('listening', resolve));
  const address = server.address() as { port: number };
  const post = async (body: string) => {
    const response = await fetch(`http://127.0.0.1:${address.port}/api/verify`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    });
    return { status: response.status, body: await response.json() as any };
  };
  try {
    const intact = await post(JSON.stringify(report));
    assert.equal(intact.status, 200);
    assert.equal(intact.body.integrity.verdict, 'INTACT');
    assert.equal(intact.body.integrity.algorithm, 'SHA-256 / verdict-v3');
    assert.equal(intact.body.integrity.probe_set_version, 'synthetic-test');
    assert.equal(intact.body.authenticity.verdict, 'NOT SIGNED');
    assert.equal(intact.body.authenticity.key_id, null);
    assert.equal(intact.body.canonical_bytes, undefined, 'Never return internal report transport');
    const altered = (await post(JSON.stringify({ ...report, target: 'changed' }))).body;
    assert.equal(altered.integrity.verdict, 'ALTERED');
    assert.equal(altered.authenticity.verdict, 'NOT SIGNED');
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
      JSON.stringify({ ...report, findings: null }),
      JSON.stringify({ ...report, findings_count: 1 })]) {
      assert.equal((await post(text)).body.integrity.verdict, 'UNREADABLE');
    }
    const malformed = (await post('{')).body;
    assert.equal(malformed.authenticity.verdict, 'UNREADABLE', 'Parsing failure is not an unsigned report');
    const keys = await fetch(`http://127.0.0.1:${address.port}/keys.json`);
    assert.equal(keys.status, 200);
    assert.deepEqual(await keys.json(), JSON.parse(readFileSync('client/public/keys.json', 'utf8')),
      'Serve exactly the explicitly configured public identities');
    assert.equal((await post(' '.repeat(1048577))).status, 413);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

test('native Ed25519 verifies a public RFC vector, rejects changed bytes and reports unknown keys', () => {
  const valid = verifyAuthenticity(true, vectorSignature, Buffer.alloc(0), [vectorKey]);
  assert.equal(valid.verdict, 'SIGNED BY');
  assert.equal(valid.key_id, vectorKey.key_id);
  assert.equal(verifyAuthenticity(true, vectorSignature, Buffer.from('changed'), [vectorKey]).verdict, 'SIGNATURE INVALID');
  assert.equal(verifyAuthenticity(true, vectorSignature, Buffer.alloc(0), []).verdict, 'UNKNOWN KEY');
  assert.equal(verifyAuthenticity(false, null, null, []).verdict, 'NOT SIGNED');
  assert.equal(verifyAuthenticity(null, null, null, []).verdict, 'UNREADABLE');
  assert.equal(verifyAuthenticity(true, vectorSignature, null, [vectorKey]).verdict, 'UNREADABLE');
  for (const signature of [
    null, [], { ...vectorSignature, alg: 'rsa' }, { ...vectorSignature, key_id: '../other' },
    { ...vectorSignature, value: '!!!' }, { ...vectorSignature, value: vectorSignature.value + '=' },
    { ...vectorSignature, private_key: 'not-accepted' },
  ]) {
    assert.equal(verifyAuthenticity(true, signature, Buffer.alloc(0), [vectorKey]).verdict, 'UNREADABLE');
  }
});

test('signature transport is exactly the CLI canonical bytes, independent of the claimed hash', () => {
  for (const report_hash of [report.report_hash, '0'.repeat(64), undefined]) {
    const response = JSON.parse(execFileSync('python3', ['-m', 'mcp_authscan.verify_upload'], {
      input: JSON.stringify({ ...report, report_hash, signature: vectorSignature }),
      encoding: 'utf8',
    }));
    const bytes = Buffer.from(response.canonical_bytes, 'base64');
    assert.equal(createHash('sha256').update(bytes).digest('hex'), report.report_hash);
    assert.deepEqual(response.signature, vectorSignature);
    assert.equal(response.signature_present, true);
    assert.equal(response.verdict, report_hash === report.report_hash ? 'INTACT' : report_hash ? 'ALTERED' : 'UNREADABLE');
  }
});

test('versioned signatures cover the exact reference envelope, not the graded hash alone', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const key: PublishedKey = {
    alg: 'ed25519', key_id: createHash('sha256').update(raw).digest('hex'),
    public_key: raw.toString('base64url'),
  };
  const adapter = (payload: object) => JSON.parse(execFileSync('python3', ['-m', 'mcp_authscan.verify_upload'], {
    input: JSON.stringify(payload), encoding: 'utf8',
  }));
  for (const version of [undefined, 1, 2, 3]) {
    const payload: any = { ...report, sig_version: version, started_at: 'excluded timestamp' };
    if (version && version >= 2) {
      payload.evidence = { scheme: 'evidence-binding-v1', states: [
        { access_class: 'anonymous', state_id: 'a'.repeat(64) },
      ] };
    }
    if (version === 3) {
      payload.provenance = { tool_version: 'synthetic', tool_manifest: 'b'.repeat(64) };
      payload.probes = [{ name: 'synthetic \u00e9', result: 'excluded' }];
    }
    const projected = JSON.parse(Buffer.from(adapter(report).canonical_bytes, 'base64').toString('utf8'));
    const envelope: any = !version || version === 1 ? projected
      : version === 2 ? { sig_version: 2, evidence: payload.evidence, report: projected }
      : { sig_version: 3, evidence: payload.evidence, report: projected,
          probes: payload.probes, provenance: payload.provenance };
    // Independent Python serialization of the specified envelope. No signed_content call.
    const expected = execFileSync('python3', ['-c',
      'import json,sys;sys.stdout.buffer.write(json.dumps(json.load(sys.stdin),sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("utf-8"))'],
      { input: JSON.stringify(envelope) });
    const before = adapter(payload);
    assert.deepEqual(Buffer.from(before.canonical_bytes, 'base64'), expected);
    payload.signature = { alg: 'ed25519', key_id: key.key_id,
      value: sign(null, expected, privateKey).toString('base64url') };
    const after = adapter(payload);
    assert.equal(after.verdict, 'INTACT');
    assert.equal(after.canonical_bytes, before.canonical_bytes, 'Signature field never signs itself');
    assert.equal(verifyAuthenticity(true, payload.signature, expected, [key]).verdict, 'SIGNED BY');
    if (version && version >= 2) {
      const altered = adapter({ ...payload, evidence: { ...payload.evidence, states: [] } });
      assert.equal(altered.verdict, 'INTACT', 'Evidence remains outside report_hash');
      assert.equal(verifyAuthenticity(true, payload.signature,
        Buffer.from(altered.canonical_bytes, 'base64'), [key]).verdict, 'SIGNATURE INVALID');
    }
  }
});

test('demonstrated reconstruction divergence names its component without accusing the signature', () => {
  for (const [payload, component] of [
    [{ ...report, sig_version: 4 }, 'sig_version'],
    [{ ...report, sig_version: 2, evidence: { scheme: 'unknown', states: [] } }, 'evidence'],
    [{ ...report, sig_version: 3, evidence: { scheme: 'evidence-binding-v1', states: [] } }, 'sig_version'],
  ] as const) {
    const result = JSON.parse(execFileSync('python3', ['-m', 'mcp_authscan.verify_upload'], {
      input: JSON.stringify(payload), encoding: 'utf8',
    }));
    assert.equal(result.verdict, 'INTACT');
    assert.equal(result.divergence, component);
    const auth = verifyAuthenticity(true, vectorSignature, null, [vectorKey], result.divergence);
    assert.equal(auth.verdict, 'DIVERGENCE');
    assert.match(auth.reason, new RegExp(component));
  }
  assert.equal(verifyAuthenticity(true, vectorSignature, Buffer.from('changed'), [vectorKey], 'report').verdict,
    'DIVERGENCE');
  assert.equal(verifyAuthenticity(true, vectorSignature, Buffer.alloc(0), [vectorKey], 'report').verdict,
    'SIGNED BY', 'A valid signature remains independent of the claimed hash');
});

test('production registry is embedded in the server and works without any runtime registry file', async () => {
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
