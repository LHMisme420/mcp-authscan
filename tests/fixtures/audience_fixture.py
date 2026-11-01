import base64
import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

CLIENT_ID = os.environ.get('FIX_CLIENT_ID', 'fixture-client')
CLIENT_SECRET = os.environ.get('FIX_CLIENT_SECRET', 'fixture-secret')
RESOURCE_MODE = os.environ.get('FIX_RESOURCE_MODE', 'strict')
PERMISSIVE = os.environ.get('FIX_AUDIENCE_PERMISSIVE', '0') == '1'
TOKENS = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def base(self):
        return 'http://127.0.0.1:%d' % self.server.server_address[1]

    def reply(self, code, payload, extra_headers=None):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def challenge(self):
        c = 'Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"' % self.base()
        self.reply(401, {'error': 'unauthorized'}, {'WWW-Authenticate': c})

    def do_GET(self):
        path = urlparse(self.path).path
        base = self.base()
        if path.startswith('/.well-known/oauth-protected-resource'):
            self.reply(200, {'resource': base + '/mcp', 'authorization_servers': [base]})
        elif path.startswith('/.well-known/oauth-authorization-server'):
            self.reply(200, {
                'issuer': base,
                'token_endpoint': base + '/token',
                'revocation_endpoint': base + '/revoke',
                'grant_types_supported': ['client_credentials'],
                'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
            })
        elif path == '/mcp':
            self.challenge()
        else:
            self.reply(404, {'error': 'not_found'})

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length).decode('utf-8', 'replace')
        if path in ('/mcp', '/', '/initialize'):
            self.mcp(raw)
        elif path == '/token':
            self.token(raw)
        elif path == '/revoke':
            self.reply(200, {})
            return
        else:
            self.reply(404, {'error': 'not_found'})

    def bearer(self):
        h = self.headers.get('Authorization') or ''
        return h[7:].strip() if h.startswith('Bearer ') else ''

    def mcp(self, raw):
        tok = self.bearer()
        if not tok or tok not in TOKENS:
            self.challenge()
            return
        aud = TOKENS[tok]['aud']
        if not PERMISSIVE and aud != self.base() + '/mcp':
            self.reply(401, {'error': 'invalid_token'}, {'WWW-Authenticate': 'Bearer error="invalid_token"'})
            return
        try:
            msg = json.loads(raw)
        except ValueError:
            msg = {}
        self.reply(200, {'jsonrpc': '2.0', 'id': msg.get('id', 0), 'result': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'serverInfo': {'name': 'audience-fixture', 'version': '1.0'}}})

    def token(self, raw):
        form = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        cid = form.get('client_id')
        csec = form.get('client_secret')
        auth = self.headers.get('Authorization') or ''
        if auth.startswith('Basic '):
            try:
                cid, csec = base64.b64decode(auth[6:]).decode().split(':', 1)
            except Exception:
                pass
        no_store = {'Cache-Control': 'no-store'}
        if cid != CLIENT_ID or csec != CLIENT_SECRET:
            self.reply(400, {'error': 'invalid_client'}, no_store)
            return
        if form.get('grant_type') != 'client_credentials':
            self.reply(400, {'error': 'unsupported_grant_type'}, no_store)
            return
        want = form.get('resource') or (self.base() + '/mcp')
        if RESOURCE_MODE == 'strict' and want != self.base() + '/mcp':
            self.reply(400, {'error': 'invalid_target'}, no_store)
            return
        tok = secrets.token_hex(16)
        TOKENS[tok] = {'aud': want}
        self.reply(200, {'access_token': tok, 'token_type': 'Bearer', 'expires_in': 3600, 'scope': 'mcp'}, no_store)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9101
    print('audience fixture on %d | client=%s | resource_mode=%s | permissive_audience=%s' % (port, CLIENT_ID, RESOURCE_MODE, PERMISSIVE), flush=True)
    HTTPServer(('127.0.0.1', port), Handler).serve_forever()


if __name__ == '__main__':
    main()
