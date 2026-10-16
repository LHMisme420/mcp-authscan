// Check essential configuration before loading optional, heavy server modules.
// Do not include connection strings or credentials in failure messages.
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing. Provision PostgreSQL through Publish before starting production.');
  process.exitCode = 1;
} else {
  await import('../build/server/index.js');
}
