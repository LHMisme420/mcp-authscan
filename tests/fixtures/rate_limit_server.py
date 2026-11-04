import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HITS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, payload, extra=None):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == '/hits':
            self.reply(200, {'hits': len(HITS)})
            return
        HITS.append(self.path)
        limit, window = self.server.limit, self.server.window
        if limit is not None and len(HITS) > limit:
            self.reply(429, {'error': 'too_many_requests'}, {'Retry-After': str(window)})
            return
        self.reply(200, {'ok': True, 'n': len(HITS)})

    do_POST = do_GET

def serve(port, limit=None, window=60):
    server = HTTPServer(('127.0.0.1', port), Handler)
    HITS.clear()
    server.limit = limit
    server.window = window
    print('rate-limit fixture %d limit=%r window=%r' % (port, limit, window), flush=True)
    return server


if sys.argv and sys.argv[0].endswith('rate_limit_server.py'):
    limit = None if len(sys.argv) < 3 or sys.argv[2] == 'open' else int(sys.argv[2])
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 9101, limit).serve_forever()
