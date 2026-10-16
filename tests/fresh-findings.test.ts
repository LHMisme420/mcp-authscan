import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createEmptyFindingsFile } from '../server/freshFindings';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const execute = promisify(execFile);

test('empty SQLite initialization works without Flask, package paths or signing credentials', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'vata-schema-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const environment = { PATH: process.env.PATH, HOME: directory, LANG: 'C.UTF-8', PYTHONNOUSERSITE: '1' };
  // Match the restricted deployment helper, not the richer test runner env.
  await execute('python3', ['-c', 'import importlib.util; assert importlib.util.find_spec("flask") is None'], { env: environment });
  const file = path.join(directory, 'empty.sqlite');
  await createEmptyFindingsFile(file, environment);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  const { stdout } = await execute('python3', ['-c', [
    'import sqlite3, sys',
    'from mcp_authscan.findings_schema import initialize_database',
    'with sqlite3.connect(sys.argv[1]) as c:',
    '    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"',
    '    for table in ("organizations", "findings", "scan_runs", "compliance_reports"):',
    '        assert c.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0',
    '    c.execute("INSERT INTO organizations(id,name,owner_user_id) VALUES(1,?,?)", ("Synthetic workspace","synthetic-owner"))',
    '    c.execute("INSERT INTO findings(org_id,severity,description) VALUES(1,?,?)", ("critical","Synthetic finding"))',
    'initialize_database(sys.argv[1])',
    'with sqlite3.connect(sys.argv[1]) as c:',
    '    assert c.execute("SELECT owner_user_id FROM organizations WHERE id=1").fetchone()[0] == "synthetic-owner"',
    '    assert c.execute("SELECT severity FROM findings").fetchall() == [("critical",)]',
    'print("empty schema valid; repeated initialization preserves findings and ownership")',
  ].join('\n'), file], { env: environment });
  assert.match(stdout, /repeated initialization preserves findings and ownership/);
});
