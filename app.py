from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
import sqlite3, os, uuid
from pathlib import Path
from contextlib import closing
from datetime import timedelta
from mcp_authscan.scanner import MCPScanner, ScanError
from mcp_authscan.repository_scan import RepositoryScanner, is_github_target, scanner_path
from mcp_authscan.tiers import reserve_scan

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET') or os.getenv('SESSION_SECRET')
if not app.config['JWT_SECRET_KEY']:
    raise RuntimeError('Set JWT_SECRET or SESSION_SECRET in Replit Secrets before starting.')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

DB_FILE = os.getenv('DB_FILE', 'vata.db')
PORT = int(os.getenv('VATA_PORT') or os.getenv('PORT', '5000'))


def init_db():
    """Preserve existing data and use the database selected by the gateway."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY, name TEXT UNIQUE, api_key TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(organizations)')}
        for name, definition in (
            ('owner_user_id', 'TEXT'),
            ('subscription_tier', "TEXT NOT NULL DEFAULT 'free'"),
            ('monthly_scan_count', 'INTEGER NOT NULL DEFAULT 0'),
            ('scan_count_month', 'TEXT'),
            ('subscription_expires_at', 'TEXT'),
        ):
            if name not in columns:
                conn.execute(f'ALTER TABLE organizations ADD COLUMN {name} {definition}')
        conn.execute('''CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY, org_id INTEGER, vector_type TEXT, severity TEXT,
            description TEXT, remediation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(findings)')}
        for name, definition in (('server_name', 'TEXT'), ('rule', 'TEXT'), ('scan_id', 'INTEGER')):
            if name not in columns:
                conn.execute(f'ALTER TABLE findings ADD COLUMN {name} {definition}')
        conn.execute('''CREATE TABLE IF NOT EXISTS compliance_reports (
            id INTEGER PRIMARY KEY, org_id INTEGER, score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL, target TEXT NOT NULL,
            status TEXT NOT NULL, total_checks INTEGER NOT NULL DEFAULT 0,
            findings_count INTEGER NOT NULL DEFAULT 0, critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0, compliance_score INTEGER, error TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMP)''')


init_db()


def database_ready():
    try:
        with closing(sqlite3.connect(Path(DB_FILE).resolve().as_uri() + '?mode=ro',
                                     uri=True, timeout=2)) as conn:
            conn.execute('SELECT id,owner_user_id FROM organizations LIMIT 0')
            conn.execute('SELECT id,org_id,severity,created_at FROM findings LIMIT 0')
            conn.execute('SELECT id,org_id,status FROM scan_runs LIMIT 0')
        return True
    except sqlite3.Error:
        return False


@app.before_request
def protect_backend():
    if request.path.startswith('/auth/'):
        return jsonify(error='Use secure account sign-in.'), 410
    if request.path.startswith(('/api/', '/internal/')):
        if os.getenv('VATA_AUTH_BRIDGE_ENABLED') == '1':
            verify_jwt_in_request()
            claims = get_jwt()
            if not claims.get('bridge') or not claims.get('owner_user_id'):
                return jsonify(error='Secure account session required.'), 403
        if not database_ready():
            return jsonify(error='Findings storage is unavailable. Preserve the database and follow the recovery guide.'), 503
        if os.getenv('VATA_AUTH_BRIDGE_ENABLED') == '1' and request.path != '/internal/provision':
            with sqlite3.connect(DB_FILE) as conn:
                owner = conn.execute('SELECT owner_user_id FROM organizations WHERE id=?',
                                     (get_jwt_identity(),)).fetchone()
            if not owner or owner[0] != get_jwt()['owner_user_id']:
                return jsonify(error='Workspace ownership conflict.'), 403


@app.get('/health')
def health():
    ready = database_ready() and scanner_path().is_file()
    return jsonify(status='ok' if ready else 'unavailable', version='2.0'), 200 if ready else 503


@app.post('/internal/provision')
@jwt_required()
def provision_owned_workspace():
    claims = get_jwt()
    if not claims.get('bridge') or not claims.get('owner_user_id'):
        return jsonify(error='Unauthorized'), 403
    try:
        org_id = int(get_jwt_identity())
    except (TypeError, ValueError):
        return jsonify(error='Invalid workspace identity.'), 400
    if org_id >= 0:
        return jsonify(error='Reserved account namespace required.'), 400
    owner = claims['owner_user_id']
    with sqlite3.connect(DB_FILE, timeout=15) as conn:
        conn.execute('BEGIN IMMEDIATE')
        existing = conn.execute('SELECT owner_user_id FROM organizations WHERE id=?', (org_id,)).fetchone()
        if existing and existing[0] != owner:
            return jsonify(error='Workspace ownership conflict.'), 409
        if not existing:
            conn.execute('INSERT INTO organizations (id,name,api_key,owner_user_id) VALUES (?,?,?,?)',
                         (org_id, f'vata_account:{org_id}', uuid.uuid4().hex, owner))
        month, count = claims.get('scan_count_month'), claims.get('monthly_scan_count', 0)
        conn.execute('''UPDATE organizations SET monthly_scan_count=
            CASE WHEN scan_count_month=? THEN max(monthly_scan_count,?) ELSE ? END,
            scan_count_month=? WHERE id=?''', (month, count, count, month, org_id))
    return jsonify(org_id=org_id)


@app.get('/')
def index():
    return '<h1>VATA Scanner</h1>'


@app.get('/api/test')
@jwt_required()
def scanner_diagnostics():
    return jsonify(scanner_exists=scanner_path().is_file(), database_ready=database_ready(),
                   repository_scans=True, live_mcp_scans=True)


def rows_for_org(query):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(query, (get_jwt_identity(),))]


@app.get('/api/findings')
@jwt_required()
def get_findings():
    return jsonify(findings=rows_for_org('''SELECT id,vector_type,severity,description,
        remediation,created_at,server_name AS server,rule,scan_id FROM findings
        WHERE org_id=? ORDER BY created_at DESC,id DESC'''))


@app.post('/api/findings')
@jwt_required()
def post_findings():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Finding request must be a JSON object.'), 400
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''INSERT INTO findings (org_id,vector_type,severity,description,remediation)
            VALUES (?,?,?,?,?)''', (get_jwt_identity(), data.get('vector_type'),
                                   data.get('severity'), data.get('description'), data.get('remediation', '')))
    return jsonify(status='ok'), 201


def organization_summary(conn, org_id):
    counts = dict(conn.execute('''SELECT UPPER(TRIM(severity)),COUNT(*) FROM findings
        WHERE org_id=? GROUP BY UPPER(TRIM(severity))''', (org_id,)))
    total = sum(counts.values())
    critical, high = counts.get('CRITICAL', 0), counts.get('HIGH', 0)
    score = 100 if not total else max(0, min(100, 100 - (critical * 100 + high * 50) / total))
    return dict(compliance_score=int(score), critical_findings=critical, high_findings=high, total_findings=total)


@app.get('/api/reports/compliance')
@jwt_required()
def compliance_report():
    with sqlite3.connect(DB_FILE) as conn:
        return jsonify(organization_summary(conn, get_jwt_identity()))


@app.get('/api/threat-intelligence')
@jwt_required()
def threat_intelligence():
    with sqlite3.connect(DB_FILE) as conn:
        counts = dict(conn.execute('''SELECT UPPER(TRIM(severity)),COUNT(*) FROM findings
            WHERE org_id=? GROUP BY UPPER(TRIM(severity))''', (get_jwt_identity(),)))
        week, month = [conn.execute(
            'SELECT COUNT(*) FROM findings WHERE org_id=? AND created_at>datetime("now",?)',
            (get_jwt_identity(), period)).fetchone()[0] for period in ('-7 days', '-30 days')]
    return jsonify(total_findings=sum(counts.values()), critical=counts.get('CRITICAL', 0),
                   high=counts.get('HIGH', 0), medium=counts.get('MEDIUM', 0), low=counts.get('LOW', 0),
                   week_trend=week, month_trend=month,
                   trend_direction='increasing' if week > month / 4 else 'decreasing')


@app.get('/api/scans/mcp')
@jwt_required()
def get_mcp_scans():
    return jsonify(scans=rows_for_org('''SELECT id,target,status,total_checks,findings_count,
        critical_count,high_count,compliance_score,error,started_at,completed_at
        FROM scan_runs WHERE org_id=? ORDER BY id DESC'''))


@app.post('/api/scan')
@app.post('/api/scans/mcp')
@jwt_required()
def run_scan():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error='Scan request must be a JSON object.'), 400
    target = data.get('target_url') or data.get('url')
    if not isinstance(target, str) or not target.strip() or len(target) > 2048:
        return jsonify(error='Enter a valid MCP server or GitHub repository URL.'), 400
    target = target.strip()
    try:
        timeout = data.get('timeout', 5)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 15:
            raise ValueError('Timeout must be between 1 and 15 seconds.')
        scanner = RepositoryScanner(target, timeout) if is_github_target(target) else MCPScanner(target, timeout)
    except (TypeError, ValueError) as error:
        return jsonify(error=str(error)), 400
    org_id = get_jwt_identity()
    if not reserve_scan(DB_FILE, org_id):
        return jsonify(error='Scan authorization denied.'), 403
    with sqlite3.connect(DB_FILE) as conn:
        scan_id = conn.execute('INSERT INTO scan_runs (org_id,target,status) VALUES (?,?,?)',
                               (org_id, scanner.target_url, 'running')).lastrowid
    try:
        checks = scanner.scan()
        failed = [check for check in checks if not check.passed]
        critical = sum(check.risk_level.value == 'CRITICAL' for check in failed)
        high = sum(check.risk_level.value == 'HIGH' for check in failed)
        with sqlite3.connect(DB_FILE) as conn:
            for check in failed:
                conn.execute('''INSERT INTO findings (org_id,vector_type,severity,description,
                    remediation,server_name,rule,scan_id) VALUES (?,?,?,?,?,?,?,?)''',
                    (org_id, check.name, check.risk_level.value,
                     f'{check.description} Target: {scanner.target_url} Endpoint: {check.endpoint}. {check.details}',
                     check.remediation, scanner.target_url, check.name, scan_id))
            score = organization_summary(conn, org_id)['compliance_score']
            conn.execute('''UPDATE scan_runs SET status='completed',total_checks=?,findings_count=?,
                critical_count=?,high_count=?,compliance_score=?,completed_at=CURRENT_TIMESTAMP
                WHERE id=? AND org_id=?''', (len(checks), len(failed), critical, high, score, scan_id, org_id))
    except Exception as error:
        message = str(error) if isinstance(error, ScanError) else 'Scan could not be completed. Please retry.'
        app.logger.warning('Scan failed: %s', type(error).__name__)
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute('''UPDATE scan_runs SET status='failed',error=?,completed_at=CURRENT_TIMESTAMP
                WHERE id=? AND org_id=?''', (message, scan_id, org_id))
        return jsonify(error=message, scan_id=scan_id, status='failed'), 502 if isinstance(error, ScanError) else 500
    return jsonify(message=f'Scan completed with {len(failed)} finding(s).', scan=dict(
        id=scan_id, target=scanner.target_url, status='completed', total_checks=len(checks),
        findings_count=len(failed), critical_count=critical, high_count=high,
        has_critical=critical > 0, compliance_score=score))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
