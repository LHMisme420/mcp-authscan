import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { compareReportGrades } from './compareReportGrades';
import { verifyReportRequest } from './verifyReportRequest';

const read = (name: string) => readFileSync(`client/public/${name}`, 'utf8');
const first = read('tollbooth-2026-11-25.json');
const second = read('tollbooth-authority-2026-11-21.json');
const report = JSON.parse(first);
const changed = (mutate: (value: any) => void) => {
  const copy = structuredClone(report);
  mutate(copy);
  return JSON.stringify(copy);
};

test('the two public Tollbooth files are not identical: verdict-v4 versus verdict-v3', () => {
  const result = compareReportGrades(first, second);
  assert.equal(result.outcome, 'different-schemes');
  assert.deepEqual(result.schemes, ['verdict-v4', 'verdict-v3']);
  assert.match(result.reason, /not classified as identical/);
  assert.deepEqual(result.probes, []);
  assert.deepEqual(result.totals, []);
  assert.deepEqual(result.runDates, ['2026-11-25T16:42:34+00:00', '2026-11-21T11:24:20+00:00']);
});

test('row order, headers, body excerpts, endpoints and timing are ignored', () => {
  const other = changed(copy => {
    copy.probes.reverse();
    copy.run_started_at = '2030-01-01T00:00:00Z';
    copy.elapsed = 999;
    copy.headers = { arbitrary: 'different' };
    for (const row of copy.probes) {
      row.headers_observed = { date: 'different' };
      row.body_excerpt = 'different';
      row.body_sha256 = 'different evidence';
      row.endpoint = 'https://different.invalid/mcp';
      row.elapsed = 999;
    }
    copy.severity_counts = Object.fromEntries(Object.entries(copy.severity_counts).reverse());
  });
  assert.equal(compareReportGrades(first, other).outcome, 'identical');
});

test('changed names and statuses identify the probe id and values in each file', () => {
  const result = compareReportGrades(first, changed(copy => {
    copy.probes[0].name = 'renamed probe';
    copy.probes[0].status = 'FAIL';
  }));
  assert.equal(result.outcome, 'different');
  assert.deepEqual(result.probes, [{
    probeId: 1, first: { name: 'issuer-identity', status: 'PASS' },
    second: { name: 'renamed probe', status: 'FAIL' },
  }]);
});

test('each differing total is named without treating missing values as zero', () => {
  const result = compareReportGrades(first, changed(copy => {
    copy.total_checks += 1;
    copy.coverage = 0.5;
    copy.findings_count += 1;
    copy.severity_counts.HIGH += 1;
  }));
  assert.deepEqual(result.totals.map(value => value.name),
    ['total_checks', 'coverage', 'findings_count', 'severity_counts']);
  assert.equal(compareReportGrades(first, changed(copy => delete copy.coverage)).outcome, 'unavailable');
});

test('missing rows are shown rather than compared by array position', () => {
  const result = compareReportGrades(first, changed(copy => copy.probes.shift()));
  assert.equal(result.outcome, 'different');
  assert.deepEqual(result.probes[0], {
    probeId: 1, first: { name: 'issuer-identity', status: 'PASS' }, second: null,
  });
});

test('malformed input, duplicate ids and missing schemes cannot be identical', () => {
  for (const input of ['{', 'null', '[]',
    changed(copy => copy.probes.push(copy.probes[0])),
    changed(copy => delete copy.hash_scheme),
    changed(copy => delete copy.probes[0].status),
    changed(copy => copy.severity_counts.HIGH = 'zero'),
  ]) assert.equal(compareReportGrades(first, input).outcome, 'unavailable', input.slice(0, 100));
  assert.match(compareReportGrades(first, changed(copy => copy.probes.push(copy.probes[0]))).reason, /duplicate probe id 1/);
});

test('both reports use the same single-file verification transport without changing bytes', async t => {
  const original = globalThis.fetch;
  const requests: { url: unknown; body: unknown; signal: unknown }[] = [];
  const verdict = { integrity: { verdict: 'INTACT', reason: 'intact', algorithm: 'SHA-256', probe_set_version: null },
    authenticity: { verdict: 'SIGNED BY', reason: 'signed', key_id: 'test-key' } };
  globalThis.fetch = async (url, init) => {
    requests.push({ url, body: init?.body, signal: init?.signal });
    return new Response(JSON.stringify(verdict), { status: 200 });
  };
  t.after(() => { globalThis.fetch = original; });
  const controller = new AbortController();
  const results = await Promise.all([verifyReportRequest(first, controller.signal), verifyReportRequest(second, controller.signal)]);
  assert.deepEqual(requests, [
    { url: '/api/verify', body: first, signal: controller.signal },
    { url: '/api/verify', body: second, signal: controller.signal },
  ]);
  assert.deepEqual(results, [verdict, verdict]);
});
