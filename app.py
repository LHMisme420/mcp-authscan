# NEW VERSION - Marker to verify this code is running
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
import sqlite3, subprocess, os, tempfile, shutil, json
from datetime import timedelta

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
JWTManager(app)

@app.route('/api/scan', methods=['POST'])
def run_scan():
    tmpdir = None
    try:
        data = request.get_json()
        target = data.get('target_url', '').strip()
        if not target:
            return jsonify({'msg': 'No target', 'findings': 0}), 200
        tmpdir = tempfile.mkdtemp()
        clone = subprocess.run(['git', 'clone', '--depth', '1', target, tmpdir], capture_output=True, text=True, timeout=120)
        if clone.returncode != 0:
            # Without this, a failed clone scans an empty dir and reports 0 findings.
            return jsonify({'msg': f'Clone failed: {clone.stderr.strip()[-300:]}', 'findings': 0}), 200
        result = subprocess.run(['python3', './mcp_authscan.py', tmpdir, '--json'], capture_output=True, text=True, timeout=300)
        report = json.loads(result.stdout)
        # Count every severity from the structured report, not by matching text lines.
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in report['findings']:
            sev = f.get('severity', '').upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        findings = report['count']
        return jsonify({'msg': f'Found {findings}', 'findings': findings, 'by_severity': by_severity}), 200
    except Exception as e:
        return jsonify({'msg': str(e), 'findings': 0}), 200
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
