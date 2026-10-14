# SQL migration for users table:
"""
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    org_id INTEGER REFERENCES organizations(id),
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT,  -- admin, analyst, viewer
    created_at TIMESTAMP
);

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    org_id INTEGER REFERENCES organizations(id),
    user_id INTEGER REFERENCES users(id),
    key TEXT UNIQUE,
    created_at TIMESTAMP
);
"""

# Flask endpoints:
from flask import Flask
from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/api/users', methods=['POST'])
@jwt_required()
def create_user():
    """Create new user in organization"""
    org_id = int(get_jwt_identity())
    email = request.json.get('email')
    role = request.json.get('role', 'analyst')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO users (org_id, email, role, created_at)
        VALUES (%s, %s, %s, %s) RETURNING id''',
        (org_id, email, role, datetime.now(timezone.utc)))
    user_id = c.fetchone()[0]
    conn.commit()
    conn.close()
    
    return jsonify({'user_id': user_id, 'email': email}), 201

@app.route('/api/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get user details"""
    org_id = int(get_jwt_identity())
    
    conn = get_db()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT id, email, role FROM users WHERE id = %s AND org_id = %s', (user_id, org_id))
    user = c.fetchone()
    conn.close()
    
    return jsonify(dict(user) if user else {'error': 'User not found'}), 200 if user else 404

@app.route('/api/orgs/<org_id>/users', methods=['GET'])
@jwt_required()
def list_users(org_id):
    """List all users in organization"""
    current_org = int(get_jwt_identity())
    if current_org != int(org_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = get_db()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute('SELECT id, email, role, created_at FROM users WHERE org_id = %s', (org_id,))
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify({'users': users}), 200
