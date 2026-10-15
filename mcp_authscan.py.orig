# ---- UPDATED Rule A2: Filter out test constants and internal utilities ----

def rule_hardcoded_creds(path, text, F):
    # Skip internal library code (utility functions, not app entry points)
    pl = str(path).lower()
    if any(seg in pl for seg in ("/internal/httpx", "/internal/httpclient", "/oryx/httpx", "/fosite/", "httpclient", "/httpx/")):
        return
    
    for m in CRED_REGEX.finditer(text):
        ev = m.group(1)
        if not ev or len(ev) > 256:
            continue
        text_line = linetext(text, m.start())
        if any(x in text_line.lower() for x in ("test", "mock", "fixture", "fake", "example", "demo")):
            continue
        line = text[max(0, m.start()-100):m.end()]
        if re.search(r"(>>>|pragma|nosec|nolint|// ignore|not a credential)", line.lower()):
            continue
        if not ev or "@" not in ev:
            # Filter: test constants (fake-*, secret-new, page-token, flag names)
            if any(bad in ev.lower() for bad in ("fake", "test", "-new", "page-", "flag", "demo", "example")):
                continue
            if re.fullmatch(r"[\w\-]+", ev) and len(ev) < 15 and ev.count("-") > 0:
                # Short hyphenated strings like "page-token", "flag-name" are not credentials
                continue
        
        # Check if in test/fixture dir
        if any(seg in str(path).lower() for seg in ("/test", "test_", "_test.go", "mock", "fixture", "fake")):
            continue
        
        add(F, "A2", "CRITICAL", "Hardcoded default credential literal",
            path, text, m.start(), ev[:80],
            "VATA:lucky-aeon default admin creds", "HIGH")


# ---- UPDATED Rule A4: Filter library utility functions ----

def rule_ssrf(path, text, F):
    # Skip internal library code and generic utility functions
    pl = path.as_posix().lower()
    if any(s in pl for s in (
        "/frontend/", "/web/", "/ui/", "/scripts/save-demo", "/skills/",
        "/internal/httpx", "/internal/httpclient",    # Generic HTTP utility libs
        "/oryx/httpx", "/httpx/", "/httpclient/",      # Utility packages
        "/fosite/integration/clients",                  # OAuth client libs
        "/examples/", "/test/", "cypress",              # Test/example code
    )):
        return
    
    seen = set()
    for rx, g in HTTP_SINKS:
        for m in rx.finditer(text):
            urlarg = m.group(g) or ""
            if _is_literal(urlarg):
                continue
            if not URL_INFLUENCE.search(urlarg):
                continue
            
            # Skip if it's a function parameter (url, endpoint, request parameter)
            # These are library functions, not app entry points
            if re.search(r"\bfunc\s+.*\(\s*\w+\s+" + re.escape(urlarg.strip().split()[0]), text[max(0,m.start()-200):m.start()]):
                continue
            
            block = enclosing_block(text, m.start())
            if SSRF_GUARD.search(block):
                continue
            
            # Skip if in /internal/ or utility package (httpx, httpclient)
            if any(x in block.lower() for x in ("func newr", "func mustnewr", "httpclient")):
                continue
            
            key = lineno(text, m.start())
            if key in seen:
                continue
            seen.add(key)
            
            # Only flag if URL comes from externally-configurable source (config, env, request)
            if not re.search(r"(cfg\.|config\.|\.URL|hookConfig\.|endpoint|upstream_)", urlarg):
                continue
            
            add(F, "A4", "MEDIUM",
                "SSRF surface: outbound request to non-literal URL, no guard in function (review each)",
                path, text, m.start(), f"url arg: {urlarg.strip()[:60]}",
                "VATA:mcpjungle OAuth DCR SSRF", "LOW")
