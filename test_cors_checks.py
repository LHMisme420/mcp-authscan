"""CI tests: CORS scanner negative/positive control"""
import subprocess
import json
import time
import requests
import sys

def start_fixture(fixture_type):
    """Start test fixture (good or bad)"""
    proc = subprocess.Popen(
        ['python3', 'test_fixtures.py', fixture_type],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1)
    return proc

def run_scanner(url):
    """Run scanner against a server"""
    with open('test_servers.json', 'w') as f:
        json.dump([{'name': 'test-server', 'url': url}], f)
    
    result = subprocess.run(
        ['python3', 'test_scanner_local.py'],
        capture_output=True,
        text=True
    )
    
    # Parse output: "test-server: N vulnerability(ies) found"
    for line in result.stdout.split('\n'):
        if 'vulnerability' in line:
            count = int(line.split(':')[1].split()[0])
            return count
    
    return -1

def test_good_fixture_no_false_positives():
    """Negative control: good fixture must return 0"""
    proc = start_fixture('good')
    time.sleep(1)
    
    try:
        count = run_scanner('http://localhost:5555')
        assert count == 0, f"Good fixture should find 0 vulns, found {count}"
        print("✓ PASS: Good fixture = 0 findings (no false positives)")
    finally:
        proc.terminate()
        proc.wait()

def test_bad_fixture_detects_vulnerability():
    """Positive control: bad fixture must return 1"""
    proc = start_fixture('bad')
    time.sleep(1)
    
    try:
        count = run_scanner('http://localhost:5556')
        assert count == 1, f"Bad fixture should find 1 vuln, found {count}"
        print("✓ PASS: Bad fixture = 1 finding (correct detection)")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == '__main__':
    print("Running CORS scanner CI tests...\n")
    
    try:
        test_good_fixture_no_false_positives()
        test_bad_fixture_detects_vulnerability()
        print("\n✓ All tests passed")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
