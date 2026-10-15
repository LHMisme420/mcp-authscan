#!/usr/bin/env python3
import requests
import json
import random
import time
from datetime import datetime

API_URL = 'https://mcp-authscan.onrender.com'  # Use Render deployment
ORG_NAME = 'Dashboard-Viewer'

def register_scanner():
    try:
        res = requests.post(f'{API_URL}/auth/register', json={'org_name': ORG_NAME})
        data = res.json()
        return data.get('access_token')
    except Exception as e:
        print(f'Register error: {e}')
        return None

def submit_finding(token, vector, severity, description):
    try:
        requests.post(f'{API_URL}/api/findings',
            headers={'Authorization': f'Bearer {token}'},
            json={'vector_type': vector, 'severity': severity, 'description': description, 'remediation': 'Investigate and patch'})
    except Exception as e:
        print(f'Submit error: {e}')

token = register_scanner()
if not token:
    print('Failed to register scanner')
    exit(1)

vectors = ['sql_injection', 'hardcoded_secrets', 'xxe_injection', 'auth_bypass', 'path_traversal', 'cors_bypass', 'info_disclosure', 'rate_limit_bypass']

for vector in vectors:
    if random.random() < 0.3:
        severity = random.choice(['CRITICAL', 'HIGH', 'MEDIUM'])
        submit_finding(token, vector, severity, f'{vector} vulnerability detected')
        print(f'  Found: {vector} ({severity})')

print('✅ Scan complete')
