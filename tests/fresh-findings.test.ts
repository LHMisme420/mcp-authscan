import { test } from 'node:test';
import assert from 'node:assert/strict';
import { initializeEmptyFindings } from '../server/freshFindings';

test('empty initialization is off by default, including in production', () => {
  assert.equal(initializeEmptyFindings('production-findings', {}), false);
  assert.equal(initializeEmptyFindings('production-findings', { NODE_ENV: 'production' }), false);
});

test('fresh approval requires production and an exact matching namespace', () => {
  assert.equal(initializeEmptyFindings('production-findings', {
    NODE_ENV: 'production', VATA_FINDINGS_INITIALIZE_EMPTY: 'production-findings',
  }), true);
  for (const env of [
    { NODE_ENV: 'development', VATA_FINDINGS_INITIALIZE_EMPTY: 'production-findings' },
    { NODE_ENV: 'production', VATA_FINDINGS_INITIALIZE_EMPTY: '1' },
    { NODE_ENV: 'production', VATA_FINDINGS_INITIALIZE_EMPTY: 'wrong-namespace' },
  ]) {
    assert.throws(() => initializeEmptyFindings('production-findings', env),
      /must explicitly name the intended production namespace/);
  }
});
