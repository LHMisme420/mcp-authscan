#!/usr/bin/env python3
"""
Vulnerable Test MCP Server - For authorized security testing only
"""
from flask import Flask, jsonify, request
import json

app = Flask(__name__)

# INTENTIONALLY VULNERABLE for testing purposes
@app.route('/tools', methods=['GET'])
def list_tools():
    """Unprotected endpoint - no auth required"""
    return jsonify({
        'tools': [
            {'name': 'execute_shell', 'description': 'Run shell commands'},
            {'name': 'read_file', 'description': 'Read files from system'},
            {'name': 'list_users', 'description': 'List system users'}
        ]
    })

@app.route('/openapi.json', methods=['GET'])
def schema_disclosure():
    """Schema disclosure vulnerability"""
    return jsonify({
        'openapi': '3.0.0',
        'info': {'title': 'Test MCP Server', 'version': '1.0.0'},
        'paths': {
            '/tools': {'get': {'description': 'List available tools'}},
            '/execute': {'post': {'description': 'Execute tool with args'}}
        }
    })

@app.route('/version', methods=['GET'])
def version_info():
    """Info disclosure - exposes internal details"""
    return jsonify({
        'version': '0.1.0-dev',
        'mcp_version': '2.0',
        'debug_mode': True,
        'internal_ip': '192.168.1.100',
        'database': 'postgres://admin:password@internal-db:5432/mcp_prod'
    })

@app.route('/tools/execute', methods=['POST'])
def execute_tool():
    """Tool execution without proper auth"""
    data = request.get_json()
    return jsonify({'status': 'executed', 'result': f'Tool {data.get("tool")} executed'})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'uptime': 12345})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)
