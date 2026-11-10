p="mcp_authscan/monolith.py"
s=open(p).read()
o="    mcp_verified = False\n    init_payload = {"
n="    mcp_verified = False\n    sv = {'status': 'NOT_OBSERVED'}\n    init_payload = {"
k="                            mcp_verified = True\n"
add="""                            r = data.get('result') or {}
                            i = r.get('serverInfo') or {}
                            sv = {'status': 'OBSERVED', 'name': i.get('name'),
                                  'version': i.get('version'),
                                  'protocolVersion': r.get('protocolVersion')}
                            print('[+] server', sv['name'], sv['version'],
                                  sv['protocolVersion'], file=sys.stderr)
"""
key = "('result' in data or 'error' in data)):\n                            mcp_verified = True\n"
ok = s.count(o) == 1 and s.count(key) == 1
print("anchors ok" if ok else "ANCHOR MISSED, nothing written")
if ok:
    s = s.replace(o, n, 1).replace(key, key + add, 1)
    s = s.replace('    if not mcp_verified:\n', '    print("[*] server_version", sv, file=sys.stderr)\n    if not mcp_verified:\n', 1)
    open(p, "w").write(s)
    print("patched")
