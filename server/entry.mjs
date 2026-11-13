// Check essential configuration before loading optional, heavy server modules.
// Do not include connection strings or credentials in failure messages.
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing. Provision PostgreSQL through Publish before starting production.');
  process.exitCode = 1;
} else {
  try {
    const { verifyRelease } = await import('../scripts/web-build-integrity.mjs');
    const { fileURLToPath } = await import('node:url');
    const release = await verifyRelease(fileURLToPath(new URL('../', import.meta.url)));
    console.log(JSON.stringify({ event: 'web_release_verified', fingerprint: release.source.fingerprint }));
    await import('../build/server/index.js');
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Web release verification failed.');
    process.exitCode = 1;
  }
}
