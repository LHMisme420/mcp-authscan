"""Answer-key fixture for probe 17 (audience-binding): the ACCEPT case.

The issuer mints a client-credentials token for a sibling resource (any resource
except the sentinel foreign-resource.invalid, which it refuses with invalid_target
so probe 11 stays PASS). The resource endpoint /mcp then HONOURS that token,
answering HTTP 200 with a real initialize result.

A 2xx carrying an initialize result is proof the resource did not check the
token's audience, so probe 17 is FAIL HIGH. Every other probe sees a correctly
locked server, so this is the one finding. Expected: HIGH, 1 finding, exit 1.

Accepted client credential: ak-client / ak-secret (supplied to the scanner as
MCPAUTHSCAN_CLIENT_ID / MCPAUTHSCAN_CLIENT_SECRET by the answer-key runner).
"""
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

P = int(sys.argv[1])
I = 'http://127.0.0.1:%d' % P
PR = json.dumps({'resource': I + '/mcp', 'authorization_servers': [I]}).encode()
AS = json.dumps({
    'issuer': I,
    'authorization_endpoint': I + '/authorize',
    'token_endpoint': I + '/token',
    'jwks_uri': I + '/jwks',
    'response_types_supported': ['code'],
    'grant_types_supported': ['authorization_code', 'client_credentials'],
    'code_challenge_methods_supported': ['S256'],
    'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
}).encode()
JW = open('bench/answer-key/jwks.json', 'rb').read()
W = 'Bearer resource_metadata="' + I + '/.well-known/oauth-protected-resource/mcp"'
CLIENT = ('ak-client', 'ak-secret')


class H(BaseHTTPRequestHandler):
    def put(s, b, c=200, extra=None):
        s.send_response(c)
        s.send_header('Content-Type', 'application/json')
        s.send_header('Cache-Control', 'no-store')
        s.send_header('Content-Length', str(len(b)))
        for k, v in (extra or {}).items():
            s.send_header(k, v)
        s.end_headers()
        s.wfile.write(b)

    def challenge(s):
        s.send_response(401)
        s.send_header('WWW-Authenticate', W)
        s.send_header('Content-Length', '0')
        s.end_headers()

    def do_GET(s):
        p = s.path
        if p.startswith('/.well-known/oauth-protected-resource'):
            return s.put(PR)
        if p.startswith('/.well-known/oauth-authorization-server'):
            return s.put(AS)
        if p == '/jwks':
            return s.put(JW)
        s.challenge()

    def _client(s, form):
        cid = form.get('client_id', [None])[0]
        csec = form.get('client_secret', [None])[0]
        auth = s.headers.get('Authorization') or ''
        if auth.startswith('Basic '):
            try:
                cid, csec = base64.b64decode(auth[6:]).decode().split(':', 1)
            except Exception:
                pass
        return cid, csec

    def do_POST(s):
        body = s.rfile.read(int(s.headers.get('Content-Length', 0) or 0))
        if s.path == '/mcp':
            # Only an authenticated presentation reaches the resource. It answers 200
            # with a JSON-RPC error -- never an initialize result.
            if (s.headers.get('Authorization') or '').startswith('Bearer '):
                return s.put(json.dumps({'jsonrpc': '2.0', 'id': 1,
                                         'result': {'protocolVersion': '2025-06-18', 'capabilities': {},
                                                    'serverInfo': {'name': 'accept', 'version': '1.0'}}}).encode())
            return s.challenge()
        if s.path == '/token':
            form = parse_qs(body.decode('utf-8', 'replace'), keep_blank_values=True)
            cid, csec = s._client(form)
            if not cid:
                return s.put(b'{"error":"invalid_client"}', 401)
            if (cid, csec) != CLIENT:
                return s.put(b'{"error":"invalid_client"}', 401)
            grant = form.get('grant_type', [''])[0]
            if grant != 'client_credentials':
                return s.put(b'{"error":"unsupported_grant_type"}', 400)
            resource = form.get('resource', [''])[0]
            if 'foreign-resource.invalid' in resource:
                # Will not mint for a resource it does not serve -> probe 11 PASS.
                return s.put(b'{"error":"invalid_target"}', 400)
            return s.put(json.dumps({'access_token': 'ak-token', 'token_type': 'Bearer',
                                     'expires_in': 3600}).encode())
        if s.path == '/revoke':
            return s.put(b'{}')
        s.put(b'{"error":"invalid_client"}', 401)

    def log_message(s, *a):
        pass


HTTPServer(('127.0.0.1', P), H).serve_forever()
