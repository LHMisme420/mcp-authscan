"""Test fixtures for header validation checks"""
from flask import Flask, request
import sys

# GOOD FIXTURE - properly validates Origin/Host
good_app = Flask('good_fixture')

@good_app.route('/mcp', methods=['GET', 'OPTIONS'])
@good_app.route('/sse', methods=['GET', 'OPTIONS'])
@good_app.route('/message', methods=['GET', 'OPTIONS'])
@good_app.route('/tools/list', methods=['GET', 'OPTIONS'])
def good_handlers():
    origin = request.headers.get('Origin', '')
    
    # Proper validation: only allow expected origins
    allowed_origins = ['http://localhost:3000', 'https://example.com']
    if origin and origin not in allowed_origins:
        return {'error': 'Origin not allowed'}, 403
    
    # CORS with credentials only for allowed origins
    if origin in allowed_origins:
        return {
            'tools': [{'name': 'test_tool'}]
        }, 200, {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
        }
    
    return {'tools': [{'name': 'test_tool'}]}, 200

# BAD FIXTURE - reflects origin (DNS rebind vulnerable)
bad_app = Flask('bad_fixture')

@bad_app.route('/mcp', methods=['GET', 'OPTIONS'])
@bad_app.route('/sse', methods=['GET', 'OPTIONS'])
@bad_app.route('/message', methods=['GET', 'OPTIONS'])
@bad_app.route('/tools/list', methods=['GET', 'OPTIONS'])
def bad_handlers():
    origin = request.headers.get('Origin', 'null')
    
    # VULNERABLE: reflects any origin
    return {
        'tools': [{'name': 'test_tool'}]
    }, 200, {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    }

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'good':
        good_app.run(port=5555, debug=False)
    else:
        bad_app.run(port=5556, debug=False)
