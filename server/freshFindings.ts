import { execFile } from 'node:child_process';
import { chmod } from 'node:fs/promises';
import { promisify } from 'node:util';

const execute = promisify(execFile);

/** Approval names one production namespace, not a blanket boolean switch. */
export function initializeEmptyFindings(namespace: string, env: NodeJS.ProcessEnv = process.env) {
  const approval = env.VATA_FINDINGS_INITIALIZE_EMPTY;
  if (!approval) return false;
  if (env.NODE_ENV !== 'production' || approval !== namespace) {
    throw new Error('Fresh findings initialization must explicitly name the intended production namespace.');
  }
  return true;
}

/** Private, throwaway SQLite only; never opens the runtime working database. */
export async function createEmptyFindingsFile(destination: string) {
  await execute('python3', ['-c', [
    'import app, sqlite3',
    'with sqlite3.connect(app.DB_FILE) as conn:',
    '    for table in ("organizations", "findings", "scan_runs", "compliance_reports"):',
    '        if conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] != 0:',
    '            raise ValueError("Fresh schema contains unexpected data")',
  ].join('\n')], {
    timeout: 60000, maxBuffer: 1024,
    // Flask validates its signing configuration during import. Do not forward
    // PostgreSQL, Clerk or connector credentials to this schema-only child.
    env: {
      PATH: process.env.PATH, PYTHONPATH: process.env.PYTHONPATH,
      HOME: process.env.HOME, LANG: process.env.LANG,
      DB_FILE: destination, VATA_PORT: '5001',
      JWT_SECRET: process.env.JWT_SECRET, SESSION_SECRET: process.env.SESSION_SECRET,
    },
  });
  await chmod(destination, 0o600);
}
