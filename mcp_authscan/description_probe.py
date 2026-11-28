"""Tool description probe: four literal tests over the tools/list response already fetched.

Reads only the tools/list items that content_probe obtained during the scan. Makes no
request, presents no credential, executes nothing, calls no model and does not judge
prose quality. Rules live in description_rules.json and description_phrases.json and are
covered by the probe-set fingerprint, so any rule change shows as a probe-set diff.

Tests, per tool, over three fields (name, description, inputSchema as canonical JSON):
  DESC-T1  hidden content: a zero-width or control character, an HTML comment opener,
           or a base64-shaped run of base64_min_run characters or more
  DESC-T2  off-domain destination: a URL, bare domain, IPv4 address or email whose
           registrable domain differs from the scanned target's
  DESC-T3  annotation contradiction: readOnlyHint true or destructiveHint false while
           the description carries a destructive verb from the fixed list
  DESC-T4  caller-directed phrase from the fixed list in description_phrases.json

Grades: one FLAGGED row per match (test id, field, quoted substring, character offset),
one CLEAN row per tool with no match, one EXCLUDED row when the tools list could not be
read or held no tools. Rows never enter counts, coverage or the exit code.
"""
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

DESCRIPTION_CALIBRATION_VERSION = "2026.11.28.1"  # MEDIUM per flag; HIGH only per the two rules in _severity

_HERE = Path(__file__).resolve().parent
RULES = json.loads((_HERE / "description_rules.json").read_text(encoding="utf-8"))
PHRASES = json.loads((_HERE / "description_phrases.json").read_text(encoding="utf-8"))

HIDDEN = re.compile(RULES["hidden_chars"])
B64 = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % int(RULES["base64_min_run"]))
URL = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s\"'<>()\[\]{}`]+")
EMAIL = re.compile(r"(?i)\b[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
BARE = re.compile(r"(?i)(?<![\w@./-])((?:[a-z0-9-]+\.)+(?:%s))(?![\w-])"
                  % "|".join(re.escape(t) for t in RULES["bare_domain_tlds"]))
VERB = re.compile(r"(?i)(?<![\w-])(%s)(?![\w-])" % "|".join(re.escape(v) for v in RULES["destructive_verbs"]))
CRED = re.compile(r"(?i)(?<![\w-])(%s)(?![\w-])" % "|".join(re.escape(w) for w in RULES["credential_words"]))
SENTENCE_END = re.compile(r"[.!?](?:\s|$)|\n")
FIELDS = ("name", "description", "inputSchema")


def registrable(host):
    """Registrable domain by a fixed rule: an IP is itself; otherwise the last two labels,
    or the last three when the last two are a listed multi-label suffix. Lowercase, no dot."""
    host = (host or "").strip().strip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    n = 3 if ".".join(labels[-2:]) in RULES["multi_label_suffixes"] else 2
    return ".".join(labels[-n:])


def _field_text(tool, field):
    v = tool.get(field)
    if v is None:
        return None
    if field == "inputSchema":
        return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return v if isinstance(v, str) else None


def _t1(text):
    for m in HIDDEN.finditer(text):
        yield m.start(), m.group(0), "zero-width or control character U+%04X" % ord(m.group(0))
    i = text.find(RULES["html_comment"])
    while i != -1:
        yield i, RULES["html_comment"], "HTML comment opener"
        i = text.find(RULES["html_comment"], i + 1)
    for m in B64.finditer(text):
        yield m.start(), m.group(0), "base64-shaped run of %d characters" % len(m.group(0))


def _t2(text, target_domain):
    taken = []
    def free(a, b):
        return all(b <= s or a >= e for s, e in taken)
    for m in URL.finditer(text):
        host = urlparse(m.group(0)).hostname or ""
        taken.append((m.start(), m.end()))
        if host and registrable(host) != target_domain:
            yield m.start(), m.group(0), "URL host %s (registrable %s) differs from target %s" % (
                host, registrable(host), target_domain)
    for m in EMAIL.finditer(text):
        if not free(m.start(), m.end()):
            continue
        taken.append((m.start(), m.end()))
        if registrable(m.group(1)) != target_domain:
            yield m.start(), m.group(0), "email domain %s differs from target %s" % (registrable(m.group(1)), target_domain)
    for m in IPV4.finditer(text):
        if not free(m.start(), m.end()):
            continue
        try:
            ip = str(ipaddress.ip_address(m.group(0)))
        except ValueError:
            continue
        taken.append((m.start(), m.end()))
        if ip != target_domain:
            yield m.start(), m.group(0), "IP %s differs from target %s" % (ip, target_domain)
    for m in BARE.finditer(text):
        if not free(m.start(), m.end()):
            continue
        taken.append((m.start(), m.end()))
        if registrable(m.group(1)) != target_domain:
            yield m.start(), m.group(1), "bare domain %s differs from target %s" % (registrable(m.group(1)), target_domain)


def _annotation_claim(tool):
    ann = tool.get("annotations")
    if not isinstance(ann, dict):
        return None
    if ann.get("readOnlyHint") is True:
        return "readOnlyHint true"
    if ann.get("destructiveHint") is False:
        return "destructiveHint false"
    return None


def _t3(tool, text):
    claim = _annotation_claim(tool)
    if not claim:
        return
    for m in VERB.finditer(text):
        yield m.start(), m.group(0), "annotation %s but description says '%s'" % (claim, m.group(0))


def _t4(text):
    low = text.lower()
    for group in ("first_action", "withhold"):
        for phrase in PHRASES[group]:
            i = low.find(phrase)
            while i != -1:
                yield i, text[i:i + len(phrase)], "caller-directed phrase (%s)" % group.replace("_", " ")
                i = low.find(phrase, i + 1)


def _sentence_span(text, offset):
    starts = [0] + [m.end() for m in SENTENCE_END.finditer(text)]
    ends = [m.end() for m in SENTENCE_END.finditer(text)] + [len(text)]
    idx = max(i for i, s in enumerate(starts) if s <= offset)
    return starts, ends, idx


def _near_credential(text, offset):
    """True when a credential/token word sits in the same sentence or an adjacent one."""
    starts, ends, idx = _sentence_span(text, offset)
    lo, hi = starts[max(0, idx - 1)], ends[min(len(ends) - 1, idx + 1)]
    return CRED.search(text[lo:hi]) is not None


def _severity(test_id, text, offset):
    if test_id == "DESC-T3":
        return "HIGH", "annotation contradicts the description (calibration %s)" % DESCRIPTION_CALIBRATION_VERSION
    if test_id == "DESC-T2" and _near_credential(text, offset):
        return "HIGH", ("off-domain destination within one sentence of a credential or token word "
                        "(calibration %s)" % DESCRIPTION_CALIBRATION_VERSION)
    return "MEDIUM", "flagged by %s on its own (calibration %s)" % (test_id, DESCRIPTION_CALIBRATION_VERSION)


def _row(probe_id, name, status, severity, basis, evidence, detail, limitation=None):
    body = json.dumps(evidence, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return {
        "probe_id": probe_id, "name": name, "status": status, "http_status": None,
        "headers_observed": {}, "body_excerpt": body,
        "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "prerequisites": ["tools/list readable without a credential"],
        "prerequisite_met": status != "EXCLUDED", "limitation": limitation,
        "probe_class": "description", "detail": detail, "severity": severity,
        "severity_basis": basis, "endpoint": None, **evidence,
    }


def excluded(reason):
    return [_row("DESC-X", "tool-description:tools-list", "EXCLUDED", None,
                 "no tools list, nothing graded", {"reason": reason}, None, limitation=reason)]


def grade(tools, target, reason=None):
    """Rows for a tools/list result. tools: the result.tools list, or None if not obtained."""
    if not isinstance(tools, list) or not tools:
        return excluded(reason or ("tools/list returned no tools" if isinstance(tools, list)
                                   else "tools/list not obtained"))
    target_domain = registrable(urlparse(target).hostname or target)
    rows = []
    for idx, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        tname = tool.get("name") if isinstance(tool.get("name"), str) and tool.get("name") else "#%d" % idx
        hits = []
        for field in FIELDS:
            text = _field_text(tool, field)
            if not text:
                continue
            for test_id, gen in (("DESC-T1", _t1(text)), ("DESC-T2", _t2(text, target_domain)),
                                 ("DESC-T3", _t3(tool, text) if field == "description" else ()),
                                 ("DESC-T4", _t4(text))):
                for offset, sub, why in gen:
                    hits.append((test_id, field, offset, sub, why, text))
        if not hits:
            rows.append(_row("DESC-0", "tool-description:%s" % tname, "CLEAN", None, "no test matched",
                             {"tool": tname}, "no test matched"))
            continue
        for test_id, field, offset, sub, why, text in sorted(set(hits), key=lambda h: (h[0], h[1], h[2], h[3])):
            sev, basis = _severity(test_id, text, offset)
            rows.append(_row(test_id, "tool-description:%s:%s:%s@%d" % (tname, test_id, field, offset), "FLAGGED",
                             sev, basis, {"tool": tname, "test_id": test_id, "field": field,
                                          "substring": sub, "offset": offset},
                             why))
    return rows or excluded("tools/list held no tool objects")


def text_lines(rows):
    out = []
    for r in rows:
        if r["status"] == "FLAGGED":
            out.append("  %s %s %s %s@%d %r [%s] basis: %s" % (r["status"], r["test_id"], r["tool"], r["field"],
                                                              r["offset"], r["substring"], r["severity"],
                                                              r["severity_basis"]))
        elif r["status"] == "CLEAN":
            out.append("  CLEAN %s" % r["tool"])
        else:
            out.append("  EXCLUDED %s" % r.get("limitation"))
    return out
