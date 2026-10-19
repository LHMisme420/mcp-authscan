from flask import Flask, jsonify, request
from authorized_scan import AuthorizedMCPScanner
import json

app = Flask(__name__)

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    data = request.json
    url = data.get('url')
    name = data.get('name', 'Target')
    
    scanner = AuthorizedMCPScanner(timeout=5)
    result = scanner.scan_server(url, name)
    
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "scanner": "authorized_v1"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
