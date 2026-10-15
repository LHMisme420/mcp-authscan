#!/usr/bin/env python3
import sqlite3
import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET', 'vata-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

DB_FILE = os.getenv('DATABASE_URL', 'vata.db')
PORT = int(os.getenv('PORT', 7777))

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY, name TEXT UNIQUE, api_key TEXT UNIQUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, org_id INTEGER, vector_type TEXT, severity TEXT, description TEXT, remediation TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (org_id) REFERENCES organizations(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS compliance_reports (id INTEGER PRIMARY KEY, org_id INTEGER, score INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (org_id) REFERENCES organizations(id))''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return '''<html><body><h1>VATA Security Platform</h1><p><a href="/dashboard.html">Dashboard</a></p></body></html>'''

@app.route('/dashboard.html')
def dashboard():
    try:
        with open('dashboard.html', 'r') as f:
            return f.read(), 200, {'Content-Type': 'text/html'}
    except:
        return 'Dashboard not found', 404

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': '2.0'}), 200

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

@app.route('/api/findings', methods=['GET'])
@jwt_required()
def get_findings():
    org_id = get_jwt_identity()
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id, vector_type, severity, description, created_at FROM findings WHERE org_id = ?', (org_id,))
        findings = [{'id': r[0], 'vector_type': r[1], 'severity': r[2], 'description': r[3], 'created_at': r[4]} for r in c.fetchall()]
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
        c.execute('INSERT INTO findings (org_id, vector_type, severity, description, remediation) VALUES (?, ?, ?, ?, ?)',
                 (org_id, data.get('vector_type'), data.get('severity'), data.get('description'), data.get('remediation', '')))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        return jsonify({'total_findings': len(recent), 'critical': recent.count('CRITICAL'), 'high': recent.count('HIGH'), 'medium': recent.count('MEDIUM'), 'week_trend': week, 'month_trend': month, 'trend_direction': 'increasing' if week > month/4 else 'decreasing'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        # Better scoring: ratio of critical+high to total findings
        if total == 0:
            score = 100
        else:
            risk_points = (critical * 100) + (high * 50)
            score = max(0, min(100, 100 - (risk_points / total)))
        return jsonify({'compliance_score': int(score), 'critical_findings': critical, 'high_findings': high}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

import subprocess


# Fixed /api/scan endpoint
import sqlite3, subprocess, os, tempfile, shutil
from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

def create_scan_endpoint(app):
    @app.route('/api/scan', methods=['POST'])
    @jwt_required()
    def run_scan():
        org_id = get_jwt_identity()
        tmpdir = None
        try:
            data = request.get_json()
            target = data.get('target', '').strip()
            
            if not target:
                return jsonify({'error': 'No target provided'}), 400
            
            # Handle GitHub URLs
            if target.startswith('http'):
                tmpdir = tempfile.mkdtemp()
                clone_result = subprocess.run(
                    ['git', 'clone', '--depth', '1', target, tmpdir],
                    capture_output=True, text=True, timeout=120
                )
                if clone_result.returncode != 0:
                    return jsonify({
                        'status': 'error',
                        'findings_count': 0,
                        'error': f'Clone failed: {clone_result.stderr[:200]}'
                    }), 400
                scan_target = tmpdir
            else:
                scan_target = target
            
            # Run scanner
            result = subprocess.run(
                ['python3', '/home/lhmisme/vata/mcp-authscan/mcp_authscan.py', scan_target],
                capture_output=True, text=True, timeout=300
            )
            
            # Parse findings
            findings = []
            for line in result.stdout.split('\n'):
                if '[CRITICAL]' in line or '[MEDIUM]' in line:
                    findings.append({
                        'severity': 'CRITICAL' if '[CRITICAL]' in line else 'MEDIUM',
                        'description': line.strip()
                    })
            
            # Store in DB
            if findings:
                conn = sqlite3.connect('/home/lhmisme/vata/mcp-authscan/findings.db')
                c = conn.cursor()
                for f in findings:
                    c.execute(
                        'INSERT INTO findings (org_id, vector_type, severity, description, remediation) VALUES (?, ?, ?, ?, ?)',
                        (org_id, 'source_code', f['severity'], f['description'], 'Review and fix')
                    )
                conn.commit()
                conn.close()
            
            return jsonify({
                'status': 'success',
                'findings_count': len(findings),
                'message': f'Scan completed with {len(findings)} finding(s).'
            }), 200
            
        except subprocess.TimeoutExpired:
            return jsonify({'error': 'Scan timeout', 'findings_count': 0}), 500
        except Exception as e:
            return jsonify({'error': str(e), 'findings_count': 0}), 500
        finally:
            if tmpdir and os.path.exists(tmpdir):
                shutil.rmtree(tmpdir, ignore_errors=True)
    
    return run_scan


run_scan_endpoint = create_scan_endpoint(app)


