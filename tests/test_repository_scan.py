"""Repository scanning checks use disposable databases and mocked network processes."""
import importlib.util
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flask_jwt_extended import create_access_token

from mcp_authscan.repository_scan import RepositoryScanner, scanner_path
from mcp_authscan.scanner import ScanError

TARGET = 'https://github.com/fixture/authorized-repository'


class RepositoryScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {
            'DB_FILE': str(Path(self.temp.name) / 'fixture.db'),
            'JWT_SECRET': 'repository-tests-synthetic-key-only-123456',
            'VATA_AUTH_BRIDGE_ENABLED': '0',
        })
        env.start()
        self.addCleanup(env.stop)
        spec = importlib.util.spec_from_file_location('repository_app_fixture', 'app.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.client = self.module.app.test_client()
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute("INSERT INTO organizations(id,name) VALUES (1,'first'),(2,'second')")
        with self.module.app.app_context():
            self.headers = {'Authorization': f'Bearer {create_access_token(identity="1")}'}
            self.other = {'Authorization': f'Bearer {create_access_token(identity="2")}'}

    def process(self, findings=None, returncode=0, stdout=None, stderr=''):
        findings = [] if findings is None else findings
        return subprocess.CompletedProcess([], returncode,
            json.dumps({'count': len(findings), 'findings': findings}) if stdout is None else stdout, stderr)

    def submit(self):
        return self.client.post('/api/scan', headers=self.headers, json={'target_url': TARGET, 'authorized': True})

    def test_json_findings_are_saved_with_real_severities_and_tenant_scope(self):
        findings = [dict(rule=f'Rule-{severity}', title=f'{severity} fixture', severity=severity,
                         file='source.js', line=3) for severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')]
        with patch('mcp_authscan.repository_scan.subprocess.run',
                   side_effect=[self.process(), self.process(findings)]) as run:
            response = self.submit()
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['scan']['findings_count'], 4)
            self.assertEqual(response.json['scan']['high_count'], 1)
            scan_id = response.json['scan']['id']
            directory = Path(run.call_args_list[0].args[0][-1])
            self.assertFalse(directory.exists())
            self.assertEqual(run.call_args_list[1].args[0][-1], '--json')
            self.assertEqual(Path(run.call_args_list[1].args[0][1]), scanner_path())
        visible = self.client.get('/api/findings', headers=self.headers).json['findings']
        self.assertEqual(len(visible), 4)
        self.assertEqual({finding['scan_id'] for finding in visible}, {scan_id})
        self.assertEqual(self.client.get('/api/findings', headers=self.other).json['findings'], [])
        self.assertEqual(self.client.get('/api/scans/mcp', headers=self.other).json['scans'], [])
        self.assertEqual(self.client.get('/api/scans/mcp', headers=self.headers).json['scans'][0]['status'], 'completed')

    def test_status_prefix_before_json_preserves_findings(self):
        finding = dict(rule='A2', title='Synthetic credential finding',
                       severity='CRITICAL', file='source.js', line=3)
        prefix = ('[*] Scanning source code directory\n'
                  'Debug context: {source scan}\n'
                  'skipped 215 test/fixture path(s); pass --include-tests to scan them\n')
        output = prefix + '  ' + json.dumps({'count': 1, 'findings': [finding]}, indent=2)
        with patch('mcp_authscan.repository_scan.subprocess.run',
                   side_effect=[self.process(), self.process(stdout=output)]):
            response = self.submit()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['scan']['findings_count'], 1)
        self.assertEqual(response.json['scan']['critical_count'], 1)
        visible = self.client.get('/api/findings', headers=self.headers).json['findings']
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0]['severity'], 'CRITICAL')

    def test_clone_failure_is_failed_not_clean_and_removes_directory(self):
        with patch('mcp_authscan.repository_scan.subprocess.run', return_value=self.process(returncode=1)) as run:
            response = self.submit()
            self.assertEqual(response.status_code, 502)
            self.assertEqual(response.json['status'], 'failed')
            self.assertFalse(Path(run.call_args.args[0][-1]).exists())
        self.assertEqual(self.client.get('/api/scans/mcp', headers=self.headers).json['scans'][0]['status'], 'failed')
        self.assertEqual(self.client.get('/api/findings', headers=self.headers).json['findings'], [])

    def test_clone_failure_logs_exit_and_only_last_500_stderr_characters(self):
        stderr = '  ' + ('prefix-not-in-log-' * 45) + ' fatal: synthetic network failure \n'
        failed = self.process(returncode=128, stderr=stderr)
        with patch('mcp_authscan.repository_scan.subprocess.run', return_value=failed), \
                self.assertLogs('mcp_authscan.repository_scan', level='WARNING') as logs:
            response = self.submit()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(logs.records[0].getMessage(),
                         f'git clone failed (exit 128): {stderr.strip()[-500:]}')
        self.assertNotIn('synthetic network failure', response.get_data(as_text=True))

    def test_execution_failures_and_bad_results_are_not_clean(self):
        for result in (self.process(returncode=2), self.process(stdout='not-json'),
                       self.process(stdout='Scanner status only\n'),
                       self.process(stdout='Scanner status\n{"count": 1,'),
                       self.process(stdout='{"count":1,"findings":[]}'),
                       self.process(findings=[{'severity': 'UNKNOWN'}])):
            with self.subTest(result=result), patch('mcp_authscan.repository_scan.subprocess.run',
                                                   side_effect=[self.process(), result]):
                self.assertEqual(self.submit().status_code, 502)
        with patch('mcp_authscan.repository_scan.subprocess.run',
                   side_effect=subprocess.TimeoutExpired('git', 35)):
            self.assertEqual(self.submit().status_code, 502)

    def test_invalid_github_urls_are_rejected_without_running_git(self):
        targets = ('http://github.com/a/b', 'https://github.com/a/b/tree/main',
                   'https://user:password@github.com/a/b', 'https://github.com/../a',
                   'https://github.com/a/b?x=y', 'https://github.com:443/a/b')
        with patch('mcp_authscan.repository_scan.subprocess.run') as run:
            for target in targets:
                response = self.client.post('/api/scan', headers=self.headers, json={'target_url': target})
                self.assertEqual(response.status_code, 400, target)
            run.assert_not_called()
        self.assertEqual(self.client.post('/api/scan', headers=self.headers,
                                         json={'target_url': '/etc/passwd'}).status_code, 400)

    def test_missing_scanner_is_an_error(self):
        with patch('mcp_authscan.repository_scan.scanner_path', return_value=Path(self.temp.name) / 'missing.py'):
            with self.assertRaises(ScanError):
                RepositoryScanner(TARGET).scan()
            with patch.object(self.module, 'scanner_path', return_value=Path(self.temp.name) / 'missing.py'):
                self.assertEqual(self.client.get('/health').status_code, 503)

    def test_missing_scanner_details_are_logged_not_returned(self):
        missing = Path(self.temp.name) / 'missing.py'
        (missing.parent / 'internal-fixture.txt').touch()
        with patch('mcp_authscan.repository_scan.scanner_path', return_value=missing), \
                patch('mcp_authscan.repository_scan.subprocess.run') as run, \
                self.assertLogs('mcp_authscan.repository_scan', level='ERROR') as logs:
            response = self.submit()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json['status'], 'failed')
        self.assertIn('scanner is unavailable', response.json['error'])
        self.assertNotIn(str(missing), response.get_data(as_text=True))
        self.assertNotIn('internal-fixture.txt', response.get_data(as_text=True))
        self.assertIn(str(missing), '\n'.join(logs.output))
        self.assertIn('internal-fixture.txt', '\n'.join(logs.output))
        run.assert_not_called()
        history = self.client.get('/api/scans/mcp', headers=self.headers).json['scans']
        self.assertEqual(history[0]['status'], 'failed')
        self.assertNotIn(str(missing), history[0]['error'])

    def test_missing_scanner_with_unreadable_directory_keeps_safe_error(self):
        with patch('mcp_authscan.repository_scan.scanner_path',
                   return_value=Path(self.temp.name) / 'missing.py'), \
                patch('mcp_authscan.repository_scan.os.listdir', side_effect=PermissionError), \
                patch('mcp_authscan.repository_scan.subprocess.run') as run, \
                self.assertLogs('mcp_authscan.repository_scan', level='ERROR') as logs:
            response = self.submit()
        self.assertEqual(response.status_code, 502)
        self.assertIn('scanner is unavailable', response.json['error'])
        self.assertIn('Unable to list scanner directory', '\n'.join(logs.output))
        run.assert_not_called()

    def test_unauthenticated_requests_cannot_scan_or_discover_paths(self):
        with patch('mcp_authscan.repository_scan.subprocess.run') as run:
            self.assertEqual(self.client.post('/api/scan', json={'target_url': TARGET, 'authorized': True}).status_code, 401)
            self.assertEqual(self.client.get('/api/test').status_code, 401)
            run.assert_not_called()
        diagnostics = self.client.get('/api/test', headers=self.headers)
        self.assertTrue(diagnostics.json['scanner_exists'])
        self.assertNotIn('cwd', diagnostics.json)
        self.assertNotIn('files_in_cwd', diagnostics.json)
        self.assertNotIn('scanner_path', diagnostics.json)

    def test_real_cli_json_contract_on_synthetic_source(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'fixture.py').write_text('print("synthetic fixture")\n')
            result = subprocess.run(['python3', str(scanner_path()), directory, '--json'],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            result_json = json.loads(result.stdout)
            self.assertEqual(result_json['count'], len(result_json['findings']))
            for finding in result_json['findings']:
                self.assertIn('title', finding)


if __name__ == '__main__':
    unittest.main()
