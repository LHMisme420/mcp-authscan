from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, origins="*")
app.config['JWT_SECRET_KEY'] = 'dev-secret-key-change-in-production'
jwt = JWTManager(app)

# PostgreSQL connection
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'vata'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

def get_db():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"DB Connection Error: {e}")
        return None

def init_db():
    conn = get_db()
    if not conn:
        print("Cannot connect to PostgreSQL. Using SQLite fallback.")
        return
    
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS organizations (
        id SERIAL PRIMARY KEY,
        name TEXT,
        api_key TEXT UNIQUE,
        created_at TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id SERIAL PRIMARY KEY,
        org_id INTEGER REFERENCES organizations(id),
        server_url TEXT,
        vector_type TEXT,
        severity TEXT,
        created_at TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS compliance_reports (
        id SERIAL PRIMARY KEY,
        org_id INTEGER REFERENCES organizations(id),
        framework TEXT,
        score INTEGER,
        breakdown TEXT,
        created_at TIMESTAMP
    )''')
    conn.commit()
    conn.close()
    print("✅ PostgreSQL database initialized")

init_db()

@app.route('/health', methods=['GET'])
def health():
    conn = get_db()
    db_status = 'ok' if conn else 'error'
    if conn:
        conn.close()
    return jsonify({'status': db_status}), 200

@app.route('/auth/register', methods=['POST'])
def register():
    try:
        org_name = request.json.get('org_name', 'DefaultOrg')
        api_key = f'vata_key_{os.urandom(16).hex()}'
        
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO organizations (name, api_key, created_at) VALUES (%s, %s, %s) RETURNING id',
                  (org_name, api_key, datetime.now(timezone.utc)))
        org_id = c.fetchone()[0]
        conn.commit()
        conn.close()
        
        return jsonify({'org_id': org_id, 'api_key': api_key}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        api_key = request.json.get('api_key')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id FROM organizations WHERE api_key = %s', (api_key,))
        org = c.fetchone()
        conn.close()
        
        if not org:
            return jsonify({'error': 'Invalid API key'}), 401
        
        access_token = create_access_token(identity=str(org[0]))
        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['GET', 'POST'])
@jwt_required()
def findings_handler():
    org_id = int(get_jwt_identity())
    
    if request.method == 'GET':
        try:
            conn = get_db()
            c = conn.cursor(cursor_factory=RealDictCursor)
            c.execute('SELECT server_url, vector_type, severity FROM findings WHERE org_id = %s ORDER BY created_at DESC', (org_id,))
            findings = [dict(row) for row in c.fetchall()]
            conn.close()
            return jsonify({'findings': findings}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            findings_list = request.json.get('findings', [])
            
            conn = get_db()
            c = conn.cursor()
            
            for finding in findings_list:
                c.execute('''INSERT INTO findings 
                    (org_id, server_url, vector_type, severity, created_at)
                    VALUES (%s, %s, %s, %s, %s)''',
                    (org_id, finding['server_url'], finding['vector_type'], 
                     finding['severity'], datetime.now(timezone.utc)))
            
            conn.commit()
            conn.close()
            
            return jsonify({'inserted': len(findings_list)}), 201
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/api/reports/compliance', methods=['POST'])
@jwt_required()
def compliance_report():
    try:
        org_id = int(get_jwt_identity())
        framework = request.json.get('framework', 'SOC2')
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT severity FROM findings WHERE org_id = %s', (org_id,))
        severities = [row[0] for row in c.fetchall()]
        conn.close()
        
        breakdown = {
            'CRITICAL': severities.count('CRITICAL'),
            'HIGH': severities.count('HIGH'),
            'MEDIUM': severities.count('MEDIUM'),
            'LOW': severities.count('LOW')
        }
        
        compliance_score = 100
        if breakdown['CRITICAL'] > 0:
            compliance_score -= 40
        if breakdown['HIGH'] > 0:
            compliance_score -= 20
        if breakdown['MEDIUM'] > 0:
            compliance_score -= 10
        
        compliance_score = max(0, compliance_score)
        
        return jsonify({
            'framework': framework,
            'compliance_score': compliance_score,
            'severity_breakdown': breakdown
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
