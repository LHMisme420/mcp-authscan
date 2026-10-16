"""Run the bundled source scanner on an explicitly selected GitHub repository."""
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from .scanner import Check, RiskLevel, ScanError


def scanner_path():
    return Path(__file__).resolve().parent.parent / 'mcp_authscan.py'


def is_github_target(target):
    return urlsplit(target).hostname == 'github.com'


class RepositoryScanner:
    def __init__(self, target_url, timeout=5):
        parsed = urlsplit(target_url)
        if (parsed.scheme != 'https' or parsed.hostname != 'github.com'
                or parsed.username or parsed.password or parsed.port
                or parsed.query or parsed.fragment
                or not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?', parsed.path)
                or any(part in {'.', '..'} for part in parsed.path.split('/'))):
            raise ValueError('Use an HTTPS GitHub repository URL: https://github.com/owner/repository.')
        self.target_url = target_url.rstrip('/')

    def scan(self):
        path = scanner_path()
        if not path.is_file():
            logger = logging.getLogger(__name__)
            logger.error('Repository scanner not found at %s', path)
            try:
                logger.error('Files in scanner directory %s: %r',
                             path.parent, sorted(os.listdir(path.parent)))
            except OSError:
                logger.exception('Unable to list scanner directory %s', path.parent)
            raise ScanError('The bundled repository scanner is unavailable. Please contact support.')
        # Never run cloned code or install a target's dependencies. Git redirects
        # and interactive credential prompts are disabled; submodules stay uninitialized.
        env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': os.devnull}
        try:
            with tempfile.TemporaryDirectory(prefix='vata-repository-') as directory:
                clone = subprocess.run(
                    ['git', '-c', 'http.followRedirects=false', '-c', 'credential.helper=',
                     'clone', '--depth', '1', '--single-branch', '--', self.target_url, directory],
                    capture_output=True, text=True, timeout=35, env=env,
                )
                if clone.returncode:
                    logging.getLogger(__name__).warning(
                        'git clone failed (exit %s): %s',
                        clone.returncode, clone.stderr.strip()[-500:])
                    raise ScanError('Unable to clone the GitHub repository. Check that it is public and accessible.')
                # The static scanner follows file symlinks, so remove symlinks
                # supplied by the target before scanning a repository we do not trust.
                for root, dirs, files in os.walk(directory, followlinks=False):
                    dirs[:] = [name for name in dirs if name != '.git']
                    for name in dirs[:] + files:
                        path = Path(root) / name
                        if path.is_symlink():
                            path.unlink()
                            if name in dirs:
                                dirs.remove(name)
                result = subprocess.run(
                    [sys.executable, str(scanner_path()), directory, '--json'],
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode != 0:
                    raise ScanError('The repository scanner failed. No clean result is available.')
                try:
                    # Extract JSON from stdout, skipping scanner's debug output
                    lines = result.stdout.split('\n')
                    json_start = -1
                    for i, line in enumerate(lines):
                        if line.strip().startswith('{'):
                            json_start = i
                            break
                    if json_start == -1:
                        raise ValueError('No JSON in scanner output')
                    json_str = '\n'.join(lines[json_start:])
                    payload = json.loads(json_str)
                    findings = payload['findings']
                    if not isinstance(findings, list) or payload['count'] != len(findings):
                        raise ValueError
                    checks = [
                        Check(name=finding['rule'], description=finding['title'],
                              endpoint=str(finding.get('file', '')).replace(directory, 'repository'),
                              method='STATIC', risk_level=RiskLevel(finding['severity']),
                              passed=False, details=f"Line: {finding.get('line', 0)}",
                              remediation=finding.get('remediation', 'Review and remediate the source finding.'))
                        for finding in findings
                    ]
                except (ValueError, KeyError, TypeError):
                    raise ScanError('The repository scanner returned invalid results.') from None
                # A completed static pass has no fixed number of HTTP checks.
                # Include its completion independently from any failing source checks.
                return [Check(name='Repository source analysis',
                              description='Static source analysis completed', endpoint='repository',
                              method='STATIC', risk_level=RiskLevel.INFO, passed=True,
                              details='Cloned code was not executed.', remediation='')] + checks
        except subprocess.TimeoutExpired:
            raise ScanError('Repository scan timed out. No clean result is available.') from None
        except OSError:
            raise ScanError('Unable to start Git or the repository scanner.') from None
