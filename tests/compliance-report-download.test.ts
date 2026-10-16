import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getCompliancePdf } from '../client/src/api';

const originalFetch = globalThis.fetch;
const originalBlob = globalThis.Blob;

function mockFetch(implementation: typeof fetch) {
  globalThis.fetch = implementation;
}

test('compliance PDF download sends cookies, requests PDF, and returns the file', async () => {
  try {
    let observedUrl = '';
    let observedInit: RequestInit | undefined;
    mockFetch(async (input, init) => {
      observedUrl = String(input);
      observedInit = init;
      return new Response('%PDF-test', {
        headers: { 'Content-Type': 'application/pdf' },
      });
    });

    const blob = await getCompliancePdf();
    assert.equal(observedUrl, '/api/reports/pdf');
    assert.equal(observedInit?.credentials, 'include');
    assert.equal(new Headers(observedInit?.headers).get('Accept'), 'application/pdf');
    assert.equal(blob.type, 'application/pdf');
    assert.equal(await blob.text(), '%PDF-test');
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.Blob = originalBlob;
  }
});

test('compliance PDF download preserves safe server errors', async () => {
  try {
    mockFetch(async () => new Response(
      JSON.stringify({ error: 'Report access is unavailable.' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } },
    ));
    await assert.rejects(getCompliancePdf(), /Report access is unavailable/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('compliance PDF download rejects a non-PDF response', async () => {
  try {
    mockFetch(async () => new Response('<h1>Not a PDF</h1>', {
      headers: { 'Content-Type': 'text/html' },
    }));
    await assert.rejects(getCompliancePdf(), /invalid PDF report/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
