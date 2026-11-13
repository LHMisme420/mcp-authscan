// This entry is deliberately separate from the old shell script. A stale
// snapshot without this file must fail, not silently ignore a new argument.
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { assertSource } from './web-build-integrity.mjs';

try {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const expected = process.argv[2];
  if (!expected || !/^[a-f0-9]{64}$/.test(expected)) throw new Error('An approved web-source fingerprint is required for deployment.');
  const source = await assertSource(root, expected);
  console.log(JSON.stringify({ event: 'deployment_source_verified', fingerprint: source.fingerprint }));
  const result = spawnSync('bash', ['scripts/deployment-build.sh'], {
    cwd: root, stdio: 'inherit',
    env: { ...process.env, VATA_EXPECTED_WEB_SOURCE: expected },
  });
  process.exitCode = result.status ?? 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Deployment source verification failed.');
  process.exitCode = 1;
}
