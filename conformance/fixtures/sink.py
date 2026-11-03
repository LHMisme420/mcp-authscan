import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open("sink9999.log", "a").write(self.path + "\n")
        self.send_response(404)
        self.end_headers()
    def do_POST(self):
        open("sink9999.log", "a").write("POST " + self.path + "\n")
        self.send_response(404)
        self.end_headers()
http.server.HTTPServer(("127.0.0.1", 9999), H).serve_forever()
