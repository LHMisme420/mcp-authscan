import { FindingsStorage } from '../server/findingsStorage';

// Run ONLY against an approved, quiesced live database (or its verified export).
// Never import app.py: that would create/alter SQLite before we validate it.
async function main() {
  if (process.argv[2] !== '--approve-live-snapshot' || process.argv.length !== 3) {
    throw new Error('Requires --approve-live-snapshot. Read docs/findings-storage.md first.');
  }
  const { DATABASE_URL, DB_FILE, VATA_FINDINGS_NAMESPACE } = process.env;
  if (!DATABASE_URL || !DB_FILE || !VATA_FINDINGS_NAMESPACE) {
    throw new Error('Set DATABASE_URL, explicit DB_FILE and VATA_FINDINGS_NAMESPACE for the intended environment.');
  }
  await new FindingsStorage(DATABASE_URL, VATA_FINDINGS_NAMESPACE, DB_FILE).seed();
  console.log('Initial private findings snapshot committed. No SQLite rows or ownership records were changed.');
}
main().catch(() => {
  console.error('Findings seed failed. Source data was not modified; verify schema, namespace, writer shutdown and source integrity. Existing backups are never overwritten.');
  process.exitCode = 1;
});
