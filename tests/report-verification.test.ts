import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import express from 'express';
import { reportVerificationRoutes } from '../server/reportVerification';

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
    assert.equal(intact.body.verdict, 'INTACT');
    assert.equal(intact.body.algorithm, 'SHA-256 / verdict-v3');
    assert.equal(intact.body.probe_set_version, 'synthetic-test');
    assert.equal((await post(JSON.stringify({ ...report, target: 'changed' }))).body.verdict, 'ALTERED');
    assert.equal((await post(JSON.stringify({ ...report, started_at: 'ignored' }))).body.verdict, 'INTACT');
    for (const text of ['{', 'null', '[]', '{"x":1,"x":2}', '{"x":NaN}',
      JSON.stringify({ ...report, schema_version: 2 }),
      JSON.stringify({ ...report, report_hash: 'short' }),
      JSON.stringify({ ...report, findings: null }),
      JSON.stringify({ ...report, findings_count: 1 })]) {
      assert.equal((await post(text)).body.verdict, 'UNREADABLE');
    }
    assert.equal((await post(' '.repeat(1048577))).status, 413);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
