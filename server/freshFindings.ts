import { execFile } from 'node:child_process';
import { chmod } from 'node:fs/promises';
import { promisify } from 'node:util';

const execute = promisify(execFile);

/** Explicit schema utility, not called during application startup. */
export async function createEmptyFindingsFile(destination: string, environment: NodeJS.ProcessEnv = process.env) {
  await execute('python3', ['-c', [
    'import sqlite3, sys',
    'from mcp_authscan.findings_schema import initialize_database',
    'initialize_database(sys.argv[1])',
    'with sqlite3.connect(sys.argv[1]) as conn:',
    '    for table in ("organizations", "findings", "scan_runs", "compliance_reports"):',
    '        if conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] != 0:',
    '            raise ValueError("Fresh schema contains unexpected data")',
  ].join('\n'), destination], {
    timeout: 60000, maxBuffer: 1024,
    // No Flask/scanner imports or credentials: fresh schemas need only stdlib.
    // Runtime Python user-package configuration must not be a prerequisite.
    env: {
      PATH: environment.PATH, HOME: environment.HOME, LANG: environment.LANG,
      PYTHONNOUSERSITE: '1',
    },
  });
  await chmod(destination, 0o600);
}
