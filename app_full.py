from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import sqlite3
import os
from datetime import timedelta
from mcp_authscan.scanner import MCPScanner, ScanError

app = Flask(__name__)
CORS(app)

# Config
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'dev-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

PORT = int(os.environ.get('PORT', 5000))
DB_FILE = os.environ.get('DB_FILE', '/tmp/vata.db')

# ============ DATABASE ============
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Organizations table
    c.execute('''CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        api_key TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Findings table
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        server_name TEXT,
        rule TEXT,
        severity TEXT,
        description TEXT,
        remediation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(org_id) REFERENCES organizations(id)
    )''')
    
    # Scans table (track scan history)
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        scan_type TEXT,
        target TEXT,
        status TEXT,
        findings_count INTEGER,
        total_checks INTEGER NOT NULL DEFAULT 0,
        critical_count INTEGER NOT NULL DEFAULT 0,
        high_count INTEGER NOT NULL DEFAULT 0,
        compliance_score INTEGER,
        error TEXT,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        FOREIGN KEY(org_id) REFERENCES organizations(id)
    )''')

    finding_columns = {row[1] for row in c.execute('PRAGMA table_info(findings)')}
    if 'scan_id' not in finding_columns:
        c.execute('ALTER TABLE findings ADD COLUMN scan_id INTEGER')
    scan_columns = {row[1] for row in c.execute('PRAGMA table_info(scans)')}
    for column, definition in (
        ('total_checks', 'INTEGER NOT NULL DEFAULT 0'),
        ('critical_count', 'INTEGER NOT NULL DEFAULT 0'),
        ('high_count', 'INTEGER NOT NULL DEFAULT 0'),
        ('compliance_score', 'INTEGER'),
        ('error', 'TEXT'),
    ):
        if column not in scan_columns:
            c.execute(f'ALTER TABLE scans ADD COLUMN {column} {definition}')
    
    conn.commit()
    conn.close()

init_db()

# ============ AUTH ENDPOINTS ============
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        org_name = data.get('org_name', f'org_{int(__import__("time").time())}')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id FROM organizations WHERE name = ?', (org_name,))
        existing = c.fetchone()
        if existing:
            org_id = existing[0]
        else:
            c.execute('INSERT INTO organizations (name, api_key) VALUES (?, ?)', (org_name, f'key_{org_name}'))
            conn.commit()
            org_id = c.lastrowid
        access_token = create_access_token(identity=str(org_id))
        conn.close()
        return jsonify({'access_token': access_token, 'org_id': org_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        org_name = data.get('org_name')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id FROM organizations WHERE name = ?', (org_name,))
        result = c.fetchone()
        conn.close()
        if not result:
            return jsonify({'error': 'Not found'}), 404
        org_id = result[0]
        access_token = create_access_token(identity=str(org_id))
        return jsonify({'access_token': access_token, 'org_id': org_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ FINDINGS API ============
@app.route('/api/findings', methods=['GET'])
@jwt_required()
def get_findings():
    org_id = get_jwt_identity()
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''SELECT id, server_name, rule, severity, description, created_at,
                     remediation, scan_id
                     FROM findings WHERE org_id = ? ORDER BY created_at DESC''', (org_id,))
        findings = [{
            'id': r[0], 'server': r[1], 'rule': r[2], 'severity': r[3],
            'description': r[4], 'created_at': r[5], 'remediation': r[6],
            'scan_id': r[7],
        } for r in c.fetchall()]
        conn.close()
        return jsonify({'findings': findings}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['POST'])
@jwt_required()
def post_findings():
    org_id = get_jwt_identity()
    try:
        data = request.get_json()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO findings (org_id, server_name, rule, severity, description, remediation) VALUES (?, ?, ?, ?, ?, ?)',
                 (org_id, data.get('server_name'), data.get('rule'), data.get('severity'), data.get('description'), data.get('remediation', '')))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ THREAT INTELLIGENCE ============
@app.route('/api/threat-intelligence', methods=['GET'])
@jwt_required()
def threat_intelligence():
    org_id = get_jwt_identity()
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT severity FROM findings WHERE org_id = ? ORDER BY created_at DESC LIMIT 100', (org_id,))
        recent = [r[0] for r in c.fetchall()]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND created_at > datetime("now", "-7 days")', (org_id,))
        week = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND created_at > datetime("now", "-30 days")', (org_id,))
        month = c.fetchone()[0]
        conn.close()
        return jsonify({
            'total_findings': len(recent), 
            'critical': recent.count('critical') + recent.count('CRITICAL'), 
            'high': recent.count('high') + recent.count('HIGH'), 
            'medium': recent.count('medium') + recent.count('MEDIUM'),
            'low': recent.count('low') + recent.count('LOW'),
            'week_trend': week, 
            'month_trend': month, 
            'trend_direction': 'increasing' if week > month/4 else 'decreasing'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ COMPLIANCE SCORING ============
@app.route('/api/reports/compliance', methods=['GET'])
@jwt_required()
def compliance_report():
    org_id = get_jwt_identity()
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "CRITICAL"', (org_id,))
        critical = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "HIGH"', (org_id,))
        high = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ?', (org_id,))
        total = c.fetchone()[0]
        conn.close()
        if total == 0:
            score = 100
        else:
            risk_points = (critical * 100) + (high * 50)
            score = max(0, min(100, 100 - (risk_points / total)))
        return jsonify({'compliance_score': int(score), 'critical_findings': critical, 'high_findings': high, 'total_findings': total}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ SCANNING ORCHESTRATION ============
@app.route('/api/scans/mcp', methods=['GET'])
@jwt_required()
def get_mcp_scans():
    org_id = get_jwt_identity()
    try:
        with sqlite3.connect(DB_FILE) as conn:
            rows = conn.execute(
                '''SELECT id, target, status, total_checks, findings_count,
                          critical_count, high_count, compliance_score, error,
                          started_at, completed_at
                   FROM scans WHERE org_id = ? AND scan_type = 'mcp'
                   ORDER BY id DESC LIMIT 10''',
                (org_id,),
            ).fetchall()
        scans = [{
            'id': row[0], 'target': row[1], 'status': row[2],
            'total_checks': row[3], 'findings_count': row[4],
            'critical_count': row[5], 'high_count': row[6],
            'compliance_score': row[7], 'error': row[8],
            'started_at': row[9], 'completed_at': row[10],
        } for row in rows]
        return jsonify({'scans': scans}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans/mcp', methods=['POST'])
@jwt_required()
def scan_mcp_servers():
    org_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({'error': 'Scan request must be a JSON object.'}), 400

    target_url = data.get('target_url') or data.get('url')
    if not target_url and isinstance(data.get('servers'), list):
        if len(data['servers']) != 1:
            return jsonify({'error': 'Submit one MCP server URL per scan.'}), 400
        target_url = data['servers'][0]
        if isinstance(target_url, str) and '://' not in target_url:
            target_url = f'http://{target_url}'
    if not isinstance(target_url, str) or not target_url.strip():
        return jsonify({'error': 'Enter an MCP server URL to scan.'}), 400
    target_url = target_url.strip()
    if len(target_url) > 2048:
        return jsonify({'error': 'The MCP server URL is too long.'}), 400

    try:
        timeout = int(data.get('timeout', 5))
        if timeout < 1 or timeout > 15:
            raise ValueError
        scanner = MCPScanner(target_url, timeout=timeout)
    except (TypeError, ValueError) as e:
        message = str(e) or 'Timeout must be between 1 and 15 seconds.'
        return jsonify({'error': message}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.execute(
                '''INSERT INTO scans (org_id, scan_type, target, status, started_at)
                   VALUES (?, 'mcp', ?, 'running', datetime('now'))''',
                (org_id, scanner.target_url),
            )
            scan_id = cursor.lastrowid
    except Exception as e:
        return jsonify({'error': f'Unable to start scan: {e}'}), 500

    try:
        checks = scanner.scan()
        failed_checks = [check for check in checks if not check.passed]
        critical_count = sum(check.risk_level.value == 'CRITICAL' for check in failed_checks)
        high_count = sum(check.risk_level.value == 'HIGH' for check in failed_checks)
        with sqlite3.connect(DB_FILE) as conn:
            for check in failed_checks:
                conn.execute(
                    '''INSERT INTO findings
                       (org_id, server_name, rule, severity, description, remediation, scan_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (
                        org_id, scanner.target_url, check.name, check.risk_level.value,
                        f'{check.description} Target: {scanner.target_url} '
                        f'Endpoint: {check.endpoint}. {check.details}',
                        check.remediation, scan_id,
                    ),
                )
            conn.execute(
                '''UPDATE scans SET status = 'completed', total_checks = ?,
                   findings_count = ?, critical_count = ?, high_count = ?,
                   completed_at = datetime('now') WHERE id = ? AND org_id = ?''',
                (len(checks), len(failed_checks), critical_count, high_count, scan_id, org_id),
            )
            critical = conn.execute(
                'SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "CRITICAL"',
                (org_id,),
            ).fetchone()[0]
            high = conn.execute(
                'SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "HIGH"',
                (org_id,),
            ).fetchone()[0]
            total = conn.execute(
                'SELECT COUNT(*) FROM findings WHERE org_id = ?', (org_id,),
            ).fetchone()[0]
            compliance_score = 100 if total == 0 else max(
                0, min(100, 100 - ((critical * 100 + high * 50) / total)),
            )
            conn.execute(
                'UPDATE scans SET compliance_score = ? WHERE id = ? AND org_id = ?',
                (int(compliance_score), scan_id, org_id),
            )
    except ScanError as e:
        error = str(e)
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                '''UPDATE scans SET status = 'failed', error = ?,
                   completed_at = datetime('now') WHERE id = ? AND org_id = ?''',
                (error, scan_id, org_id),
            )
        return jsonify({'error': error, 'scan_id': scan_id, 'status': 'failed'}), 502
    except Exception as e:
        error = f'Scan could not be completed: {e}'
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                '''UPDATE scans SET status = 'failed', error = ?,
                   completed_at = datetime('now') WHERE id = ? AND org_id = ?''',
                (error, scan_id, org_id),
            )
        return jsonify({'error': error, 'scan_id': scan_id, 'status': 'failed'}), 500

    summary = {
        'id': scan_id,
        'target': scanner.target_url,
        'status': 'completed',
        'total_checks': len(checks),
        'findings_count': len(failed_checks),
        'critical_count': critical_count,
        'high_count': high_count,
        'compliance_score': int(compliance_score),
        'has_critical': critical_count > 0,
    }
    return jsonify({
        'scan': summary,
        'message': (
            f"Scan completed with {critical_count} critical finding(s)."
            if critical_count else f"Scan completed with {len(failed_checks)} finding(s)."
        ),
    }), 200

# ============ HEALTH CHECK ============
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
