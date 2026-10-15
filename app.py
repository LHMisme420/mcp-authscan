# NEW VERSION - Marker to verify this code is running
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
import sqlite3, subprocess, os, tempfile, shutil
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
        subprocess.run(['git', 'clone', '--depth', '1', target, tmpdir], capture_output=True, timeout=120)
        result = subprocess.run(['python3', './mcp_authscan.py', tmpdir], capture_output=True, text=True, timeout=300)
        findings = len([1 for line in result.stdout.split('\n') if '[CRITICAL' in line or '[MEDIUM' in line])
        return jsonify({'msg': f'Found {findings}', 'findings': findings}), 200
    except Exception as e:
        return jsonify({'msg': str(e), 'findings': 0}), 200
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
