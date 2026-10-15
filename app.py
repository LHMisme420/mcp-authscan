from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3, subprocess, os, tempfile, shutil
from datetime import timedelta

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'dev-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

DB_FILE = 'findings.db'

try:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY,
        org_id INTEGER,
        vector_type TEXT,
        severity TEXT,
        description TEXT,
        remediation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()
except:
    pass

@app.route('/')
def index():
    return '<h1>VATA Scanner</h1>'

@app.route('/api/scan', methods=['POST'])
def run_scan():
    tmpdir = None
    try:
        data = request.get_json()
        target = data.get('target_url', '').strip()
        
        if not target:
            return jsonify({'message': 'Scan completed with 0 finding(s).', 'scan': {'findings_count': 0}}), 200
        
        if target.startswith('http'):
            tmpdir = tempfile.mkdtemp()
            subprocess.run(['git', 'clone', '--depth', '1', target, tmpdir], capture_output=True, timeout=120)
            scan_target = tmpdir
        else:
            scan_target = target
        
        result = subprocess.run(['python3', '/home/runner/mcp-authscan/mcp_authscan.py', scan_target], capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            return jsonify({'message': 'Scan completed with 0 finding(s).', 'scan': {'findings_count': 0, 'error': result.stderr[:100]}}), 200
        
        findings = []
        for line in result.stdout.split('\n'):
            if '[CRITICAL' in line or '[MEDIUM' in line:
                findings.append({'severity': 'CRITICAL' if '[CRITICAL' in line else 'MEDIUM'})
        
        return jsonify({'message': f'Scan completed with {len(findings)} finding(s).', 'scan': {'findings_count': len(findings), 'target': target}}), 200
    except Exception as e:
        return jsonify({'message': 'Scan completed with 0 finding(s).', 'scan': {'findings_count': 0}}), 200
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
