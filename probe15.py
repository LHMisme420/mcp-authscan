import http.client
import json
import urllib.parse

RULE = "MCP-TRANSPORT-1"

def sibling(url):
	parts = urllib.parse.urlsplit(url)
	path = parts.path.rstrip("/")
	if not path.endswith("/mcp"):
		return None
	return path[:-4] + "/sse"

def grade(status, ctype, body):
	if status in (401, 403):
		return "PASS", "sibling transport answered " + str(status) + " with authentication enforced"
	if status == 200:
		if "text/event-stream" in ctype:
			return "FAIL", "sibling transport streamed with no credential"
		try:
			doc = json.loads(body.decode("utf-8", "replace") or "{}")
		except ValueError:
			doc = None
		if isinstance(doc, dict) and "jsonrpc" in doc:
			return "FAIL", "sibling transport answered JSON-RPC with no credential"
		return "EXCLUDED", "200 whose body cannot be graded"
	return "EXCLUDED", "sibling transport answered " + str(status) + " and cannot be graded"

def probe15(url, allow):
	parts = urllib.parse.urlsplit(url)
	sse = sibling(url)
	if sse is None:
		return "EXCLUDED", "target path does not end in mcp"
	host = parts.hostname
	if allow is not None and host not in allow:
		return "EXCLUDED", "sibling host not declared"
	port = parts.port
	if port is None:
		port = 443 if parts.scheme == "https" else 80
	if parts.scheme == "https":
		conn = http.client.HTTPSConnection(host, port, timeout=10)
	else:
		conn = http.client.HTTPConnection(host, port, timeout=10)
	headers = {}
	headers["Content-Type"] = "application/json"
	headers["Accept"] = "application/json, text/event-stream"
	try:
		conn.request("POST", sse, body=b"{}", headers=headers)
		resp = conn.getresponse()
		status = resp.status
		ctype = (resp.getheader("Content-Type") or "").lower()
		body = resp.read(4096)
	except Exception as exc:
		return "EXCLUDED", "sibling transport unreachable " + str(exc)
	finally:
		conn.close()
	return grade(status, ctype, body)
