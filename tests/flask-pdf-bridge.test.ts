import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeScannerResponse } from '../server/flaskBridge';

test('private scanner PDF responses retain their bytes and status', async () => {
  const response = new Response('%PDF-private-scan', {
    status: 200,
    headers: { 'Content-Type': 'application/pdf; charset=binary' },
  });
  const result = await decodeScannerResponse(response);
  assert.equal(result.status, 200);
  assert.ok(result.pdf);
  assert.equal(result.pdf?.toString(), '%PDF-private-scan');
});

test('private scanner JSON errors still pass through as JSON', async () => {
  const response = new Response(JSON.stringify({ error: 'not authorized' }), {
    status: 403,
    headers: { 'Content-Type': 'application/json' },
  });
  const result = await decodeScannerResponse(response);
  assert.equal(result.status, 403);
  assert.deepEqual(result.data, { error: 'not authorized' });
  assert.equal('pdf' in result, false);
});
