"""mcp-authscan-verify: an MCP stdio server with one tool, `verify`.

Trust model:
- The trusted keyring is the operator's, not the caller's. It is read once at startup from the
  path in MCP_AUTHSCAN_TRUSTED_KEYS, set by whoever launches the server. The tool takes no
  keys argument and refuses one if sent. A signature that verifies against a key the caller
  chose proves only that the caller holds that key, so the caller must not be able to choose.
  With no keyring configured, signatures are reported NOT CHECKED, never trusted.
- Reports are read only from inside the evidence directory (MCP_AUTHSCAN_EVIDENCE, default
  ~/mcp-authscan-evidence). The path is opened one component at a time from the evidence
  directory with O_NOFOLLOW, so no symlink or swapped directory can lead outside it, and the
  bytes are read once. The hash and the signature are checked on that one read.
- Malformed requests get JSON-RPC errors and the server keeps serving. Error text never
  echoes exception messages, paths or file contents.
"""
import base64
import hashlib
import json
import os
import stat
import sys

from mcp_authscan.report_verify import authenticity, verify_payload

VERSION = "0.2.0"
MAX_REPORT_BYTES = 5 * 1024 * 1024
MAX_KEYRING_BYTES = 1024 * 1024

TOOL = {
    "name": "verify",
    "description": ("Recompute the hash of an mcp-authscan report in the evidence directory and check its "
                    "signature against the operator's trusted keyring."),
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string",
                                "description": "Path of the report JSON, inside the evidence directory"}},
        "required": ["path"],
        "additionalProperties": False,
    },
    "annotations": {"title": "Verify report", "readOnlyHint": True, "destructiveHint": False,
                    "idempotentHint": True, "openWorldHint": False},
}


class Refused(Exception):
    """A request the server will not carry out. The message is fixed text, safe to return."""


def log(event):
    # Operator-side log on stderr: an event name and an exception type, never a path or content.
    sys.stderr.write("mcp-authscan-verify: %s\n" % event)
    sys.stderr.flush()


def out(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def error(mid, code, message):
    out({"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}})


def text_result(mid, text):
    out({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}})


def evidence_dir():
    """(resolved, as written): the operator's evidence directory, resolved, and as configured."""
    base = os.path.abspath(os.path.expanduser(os.environ.get("MCP_AUTHSCAN_EVIDENCE") or "~/mcp-authscan-evidence"))
    return os.path.realpath(base), base


def _read_regular(fd, limit):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise Refused("not a regular file")
    if st.st_size > limit:
        raise Refused("file is larger than %d bytes" % limit)
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:                     # grew after fstat
            raise Refused("file is larger than %d bytes" % limit)
        chunks.append(chunk)
    return b"".join(chunks)


def read_confined(bases, requested):
    """Bytes of `requested`, which must name a regular file inside `base`.

    Walks from an fd on `base`, one component at a time, each opened with O_NOFOLLOW (directories
    also with O_DIRECTORY). A symlink anywhere in the path, '..', or a component swapped for a
    symlink between check and use, fails to open instead of leading outside `base`."""
    if not isinstance(requested, str) or not requested or "\x00" in requested:
        raise Refused("path must be a non-empty string")
    full = os.path.abspath(os.path.expanduser(requested))
    # Lexical containment first (no filesystem access, so no race); then the O_NOFOLLOW walk.
    # The operator's evidence directory may itself be a symlink: a path under either its resolved
    # or its configured spelling is accepted, and the walk always starts from the resolved one.
    base = bases[0]
    for root in bases:
        if full != root and os.path.commonpath([full, root]) == root:
            parts = os.path.relpath(full, root).split(os.sep)
            break
    else:
        raise Refused("report must be a file inside the evidence directory")
    if any(p in ("", ".", "..") for p in parts):
        raise Refused("report must be a file inside the evidence directory")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow:
        raise Refused("this platform cannot open files without following symlinks")
    fds = []
    try:
        fds.append(os.open(base, os.O_RDONLY | os.O_DIRECTORY | cloexec))
        for part in parts[:-1]:
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | nofollow | cloexec, dir_fd=fds[-1]))
        fds.append(os.open(parts[-1], os.O_RDONLY | nofollow | cloexec | getattr(os, "O_NONBLOCK", 0),
                           dir_fd=fds[-1]))
        return _read_regular(fds[-1], MAX_REPORT_BYTES)
    except OSError:
        raise Refused("report must be a readable regular file inside the evidence directory, reached without symlinks")
    finally:
        for fd in reversed(fds):
            os.close(fd)


def load_keyring():
    """The operator's trusted keys, or None if none is configured. Exits if one is configured
    but unusable: a verifier that silently ran without its keyring would report NOT CHECKED
    where the operator expected a trust decision."""
    path = os.environ.get("MCP_AUTHSCAN_TRUSTED_KEYS")
    if not path:
        log("no MCP_AUTHSCAN_TRUSTED_KEYS set; signatures will be reported NOT CHECKED")
        return None
    try:
        fd = os.open(os.path.expanduser(path), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            raw = _read_regular(fd, MAX_KEYRING_BYTES)
        finally:
            os.close(fd)
        keys = json.loads(raw.decode("utf-8"))
    except (OSError, Refused, ValueError, UnicodeDecodeError) as e:
        log("trusted keyring unreadable or not JSON (%s); refusing to start" % type(e).__name__)
        sys.exit(2)
    if not isinstance(keys, list) or not keys:
        log("trusted keyring must be a non-empty JSON list; refusing to start")
        sys.exit(2)
    for entry in keys:
        ok = (isinstance(entry, dict) and entry.get("alg") == "ed25519"
              and isinstance(entry.get("public_key"), str) and isinstance(entry.get("key_id"), str))
        if ok:
            try:
                pub = base64.urlsafe_b64decode(entry["public_key"] + "=" * (-len(entry["public_key"]) % 4))
                ok = len(pub) == 32 and hashlib.sha256(pub).hexdigest() == entry["key_id"]
            except (ValueError, TypeError):
                ok = False
        if not ok:
            log("trusted keyring has an entry that is not {alg: ed25519, key_id: sha256(public_key), public_key}; "
                "refusing to start")
            sys.exit(2)
    log("trusted keyring loaded: %d key(s)" % len(keys))
    return keys


def verify_tool(args, keyring):
    if not isinstance(args, dict):
        raise Refused("arguments must be an object")
    if "keys" in args:
        raise Refused("keys are not accepted from the caller; the trusted keyring is set by the operator "
                      "(MCP_AUTHSCAN_TRUSTED_KEYS)")
    extra = sorted(set(args) - {"path"})
    if extra:
        raise Refused("unknown argument")
    raw = read_confined(evidence_dir(), args.get("path"))
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise Refused("report is not valid UTF-8 JSON")
    if not isinstance(payload, dict):
        raise Refused("report is not a JSON object")
    verdict, detail = verify_payload(payload)
    if keyring is None:
        signature = "SIGNATURE NOT CHECKED (no trusted keyring configured by the operator)"
    else:
        signature = authenticity(payload, keyring)
    return "VERDICT %s\nDETAIL %s\nSIGNATURE %s" % (verdict, detail, signature)


def handle(req, keyring):
    if not isinstance(req, dict):
        error(None, -32600, "invalid request")
        return
    mid = req.get("id")
    method = req.get("method")
    params = req.get("params", {})
    if not isinstance(method, str) or not isinstance(params, (dict, list)):
        if mid is not None:
            error(mid, -32600, "invalid request")
        return
    if method == "initialize":
        pv = params.get("protocolVersion") if isinstance(params, dict) else None
        out({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": pv if isinstance(pv, str) else "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mcp-authscan-verify", "version": VERSION}}})
    elif method == "tools/list":
        out({"jsonrpc": "2.0", "id": mid, "result": {"tools": [TOOL]}})
    elif method == "tools/call":
        if mid is None:
            return
        if not isinstance(params, dict) or params.get("name") != "verify":
            error(mid, -32602, "unknown tool")
            return
        try:
            text = verify_tool(params.get("arguments", {}), keyring)
        except Refused as e:
            text = "ERROR " + str(e)
        except Exception as e:                       # never echo internals to the caller
            log("verification failed: %s" % type(e).__name__)
            text = "ERROR verification failed (internal error)"
        text_result(mid, text)
    elif mid is not None:
        error(mid, -32601, "unknown method")


def serve():
    keyring = load_keyring()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            error(None, -32700, "parse error")
            continue
        try:
            handle(req, keyring)
        except Exception as e:                       # one bad request must not end the server
            log("request handling failed: %s" % type(e).__name__)
            mid = req.get("id") if isinstance(req, dict) else None
            if mid is not None:
                error(mid, -32603, "internal error")


if __name__ == "__main__":
    serve()
