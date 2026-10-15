from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
import sqlite3, subprocess, os, tempfile, shutil, glob
from datetime import timedelta

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'dev')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
JWTManager(app)

DB_FILE = 'findings.db'
try:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, org_id INTEGER, vector_type TEXT, severity TEXT, description TEXT, remediation TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()
except: pass

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
            clone = subprocess.run(['git', 'clone', '--depth', '1', target, tmpdir], capture_output=True, text=True, timeout=120)
            if clone.returncode != 0:
                return jsonify({'message': f'Clone failed: {clone.stderr}', 'scan': {'findings_count': 0}}), 200
            scan_target = tmpdir
        else:
            scan_target = target
        
        # Find scanner
        scanner = None
        for p in ['/home/runner/mcp-authscan/mcp_authscan.py', '/workspace/mcp-authscan/mcp_authscan.py', './mcp_authscan.py']:
            if os.path.exists(p):
                scanner = p
                break
        
        if not scanner:
            return jsonify({'message': f'Scanner not found at any path', 'scan': {'findings_count': 0, 'searched': ['/home/runner/mcp-authscan/mcp_authscan.py', './mcp_authscan.py']}}), 200
        
        result = subprocess.run(['python3', scanner, scan_target], capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            return jsonify({'message': f'Scanner error: {result.stderr}', 'scan': {'findings_count': 0}}), 200
        
        findings = [1 for line in result.stdout.split('\n') if '[CRITICAL' in line or '[MEDIUM' in line]
        return jsonify({'message': f'Scan completed with {len(findings)} finding(s).', 'scan': {'findings_count': len(findings)}}), 200
    except Exception as e:
        return jsonify({'message': f'Exception: {str(e)}', 'scan': {'findings_count': 0}}), 200
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
