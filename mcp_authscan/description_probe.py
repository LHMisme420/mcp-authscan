"""Description probe: four literal tests over the tools/prompts/resources lists already fetched.

Reads only the list items that content_probe obtained during the scan. Makes no request,
presents no credential, executes nothing, calls no model and does not judge prose quality.
Rules live in description_rules.json and description_phrases.json and are covered by the
probe-set fingerprint, so any rule change shows as a probe-set diff.

Tests, per item, over the fields listed in the rules (name, title, description, inputSchema
and prompt arguments as canonical JSON, resource uri):
  DESC-T1  hidden content: a zero-width, bidi, tag or control character; an HTML comment
           opener; a base64-shaped run (standard or URL-safe alphabet) of base64_min_run or
           more; a word mixing Latin with Cyrillic or Greek letters (lookalike spoofing)
  DESC-T2  off-domain destination: a URL (including protocol-relative), bare domain
           (including [.]/(dot) obfuscation), IPv4 or integer IP, or email whose registrable
           domain differs from the scanned target's
  DESC-T3  annotation contradiction: readOnlyHint true or destructiveHint false while the
           description carries a destructive verb from the fixed list (tools only)
  DESC-T4  caller-directed phrase from description_phrases.json, matched after NFKC
           folding, hidden-character removal and whitespace collapsing; the offset is
           mapped back to the original text

Grades: one FLAGGED row per match (test id, field, quoted substring, character offset),
one CLEAN row per item with no match, one EXCLUDED row when the tools list could not be
read or held no tools. Prompts and resources are graded when the server listed them.
Rows never enter counts, coverage or the exit code.

Known limit, by design: a literal test cannot catch an instruction reworded in plain
language. That needs judgment of prose, which this probe does not do.
"""
import hashlib
import ipaddress
import json
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

DESCRIPTION_CALIBRATION_VERSION = "2026.11.28.1"  # MEDIUM per flag; HIGH only per the two rules in _severity

_HERE = Path(__file__).resolve().parent
RULES = json.loads((_HERE / "description_rules.json").read_text(encoding="utf-8"))
PHRASES = json.loads((_HERE / "description_phrases.json").read_text(encoding="utf-8"))

HIDDEN = re.compile(RULES["hidden_chars"])
B64 = re.compile(r"[%s]{%d,}={0,2}" % (RULES["base64_alphabet"], int(RULES["base64_min_run"])))
URL = re.compile(r"(?i)\b(?:https?|ftp|wss?)://[^\s\"'<>()\[\]{}`]+")
PROTO_REL = re.compile(r"(?i)(?<![:\w/])//((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])")
EMAIL = re.compile(r"(?i)\b[\w.+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,})\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_TLDS = "|".join(re.escape(t) for t in RULES["bare_domain_tlds"])
BARE = re.compile(r"(?i)(?<![\w@./-])((?:[a-z0-9-]+\.)+(?:%s))(?![\w-])" % _TLDS)
_OBF = "|".join(re.escape(d) for d in RULES["obfuscated_dots"])
OBFUSCATED = re.compile(r"(?i)(?<![\w@])((?:[a-z0-9-]+(?:%s))+(?:%s))(?![\w-])" % (_OBF, _TLDS))
WORD = re.compile(r"\w{2,}")
VERB = re.compile(r"(?i)(?<![\w-])(%s)(?![\w-])" % "|".join(re.escape(v) for v in RULES["destructive_verbs"]))
CRED = re.compile(r"(?i)(?<![\w-])(%s)(?![\w-])" % "|".join(re.escape(w) for w in RULES["credential_words"]))
SENTENCE_END = re.compile(r"[.!?](?:\s|$)|\n")
FIELDS = tuple(RULES["fields"])
KINDS = (("tool", "tools"), ("prompt", "prompts"), ("resource", "resources"))


def _ip_of(host):
    host = host.strip("[]")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:  # integer forms: 3232235777, 0xC0A80001
        n = int(host, 16) if host.lower().startswith("0x") else int(host) if host.isdigit() else None
        return str(ipaddress.ip_address(n)) if n is not None and n < 2 ** 32 else None
    except ValueError:
        return None


def registrable(host):
    """Registrable domain by a fixed rule: an IP (any form) is its canonical address; otherwise
    the last two labels, or the last three when the last two are a listed multi-label suffix."""
    host = (host or "").strip().strip(".").lower()
    ip = _ip_of(host)
    if ip:
        return ip
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    n = 3 if ".".join(labels[-2:]) in RULES["multi_label_suffixes"] else 2
    return ".".join(labels[-n:])


def _field_text(item, field):
    v = item.get(field)
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return v if isinstance(v, str) else None


def _scripts(word):
    out = set()
    for ch in word:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            for s in RULES["mixed_scripts"]:
                if name.startswith(s):
                    out.add(s)
    return out


def _t1(text):
    for m in HIDDEN.finditer(text):
        yield m.start(), m.group(0), "hidden character U+%04X" % ord(m.group(0))
    i = text.find(RULES["html_comment"])
    while i != -1:
        yield i, RULES["html_comment"], "HTML comment opener"
        i = text.find(RULES["html_comment"], i + 1)
    for m in B64.finditer(text):
        yield m.start(), m.group(0), "base64-shaped run of %d characters" % len(m.group(0))
    for m in WORD.finditer(text):
        s = _scripts(m.group(0))
        if "LATIN" in s and len(s) > 1:
            yield m.start(), m.group(0), "word mixes scripts: %s" % "+".join(sorted(s))


def _t2(text, target_domain):
    taken = []

    def claim(a, b):
        if all(b <= s or a >= e for s, e in taken):
            taken.append((a, b))
            return True
        return False

    for m in URL.finditer(text):
        claim(m.start(), m.end())
        host = urlparse(m.group(0)).hostname or ""
        if host and registrable(host) != target_domain:
            yield m.start(), m.group(0), "URL host %s (registrable %s) differs from target %s" % (
                host, registrable(host), target_domain)
    for rx, kind, grp in ((PROTO_REL, "protocol-relative host", 1), (EMAIL, "email domain", 1),
                          (OBFUSCATED, "obfuscated domain", 1), (IPV4, "IP", 0), (BARE, "bare domain", 1)):
        for m in rx.finditer(text):
            if not claim(m.start(), m.end()):
                continue
            host = m.group(grp)
            if kind == "obfuscated domain":
                host = re.sub(r"(?i)%s" % _OBF, ".", host)
            if kind == "IP" and _ip_of(host) is None:
                continue
            if registrable(host) != target_domain:
                yield m.start(), m.group(0), "%s %s differs from target %s" % (kind, registrable(host), target_domain)


def _annotation_claim(item):
    ann = item.get("annotations")
    if not isinstance(ann, dict):
        return None
    if ann.get("readOnlyHint") is True:
        return "readOnlyHint true"
    if ann.get("destructiveHint") is False:
        return "destructiveHint false"
    return None


def _t3(item, text):
    claim = _annotation_claim(item)
    if not claim:
        return
    for m in VERB.finditer(text):
        yield m.start(), m.group(0), "annotation %s but description says '%s'" % (claim, m.group(0))


def _folded(text):
    """(normalized lowercase text, index map to original offsets): NFKC, hidden chars removed,
    whitespace runs collapsed to one space."""
    out, idx, prev_space = [], [], False
    for i, ch in enumerate(text):
        if HIDDEN.match(ch):
            continue
        for c in unicodedata.normalize("NFKC", ch).lower():
            if c.isspace():
                if prev_space:
                    continue
                c, prev_space = " ", True
            else:
                prev_space = False
            out.append(c)
            idx.append(i)
    return "".join(out), idx


def _t4(text):
    low, idx = _folded(text)
    for group in ("first_action", "withhold"):
        for phrase in PHRASES[group]:
            i = low.find(phrase)
            while i != -1:
                start, end = idx[i], idx[i + len(phrase) - 1] + 1
                yield start, text[start:end], "caller-directed phrase (%s)" % group.replace("_", " ")
                i = low.find(phrase, i + 1)


def _near_credential(text, offset):
    """True when a credential/token word sits in the same sentence or an adjacent one."""
    starts = [0] + [m.end() for m in SENTENCE_END.finditer(text)]
    ends = [m.end() for m in SENTENCE_END.finditer(text)] + [len(text)]
    idx = max(i for i, s in enumerate(starts) if s <= offset)
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
        "prerequisites": ["list readable without a credential"],
        "prerequisite_met": status != "EXCLUDED", "limitation": limitation,
        "probe_class": "description", "detail": detail, "severity": severity,
        "severity_basis": basis, "endpoint": None, **evidence,
    }


def excluded(reason):
    return [_row("DESC-X", "tool-description:tools-list", "EXCLUDED", None,
                 "no tools list, nothing graded", {"reason": reason}, None, limitation=reason)]


def _grade_items(kind, items, target_domain):
    rows = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        label = next((item[k] for k in ("name", "uri") if isinstance(item.get(k), str) and item.get(k)), "#%d" % idx)
        hits = set()
        for field in FIELDS:
            text = _field_text(item, field)
            if not text:
                continue
            for test_id, gen in (("DESC-T1", _t1(text)), ("DESC-T2", _t2(text, target_domain)),
                                 ("DESC-T3", _t3(item, text) if kind == "tool" and field == "description" else ()),
                                 ("DESC-T4", _t4(text))):
                for offset, sub, why in gen:
                    hits.add((test_id, field, offset, sub, why, text))
        prefix = "%s-description:%s" % (kind, label)
        if not hits:
            rows.append(_row("DESC-0", prefix, "CLEAN", None, "no test matched",
                             {"kind": kind, "tool": label}, "no test matched"))
            continue
        for test_id, field, offset, sub, why, text in sorted(hits, key=lambda h: (h[0], h[1], h[2], h[3])):
            sev, basis = _severity(test_id, text, offset)
            # The quoted substring (ASCII-escaped) is part of the name, so report_hash (verdict-v4 row
            # projection: probe_id, name, status, ..., severity) covers it as well as the offset.
            quoted = json.dumps(sub, ensure_ascii=True)
            rows.append(_row(test_id, "%s:%s:%s@%d:%s" % (prefix, test_id, field, offset, quoted), "FLAGGED", sev, basis,
                             {"kind": kind, "tool": label, "test_id": test_id, "field": field,
                              "substring": sub, "offset": offset}, why))
    return rows


def grade(tools, target, reason=None, prompts=None, resources=None):
    """Rows for the lists content_probe fetched. tools: result.tools, or None if not obtained.
    prompts/resources: graded only when the server listed them."""
    if not isinstance(tools, list) or not tools:
        return excluded(reason or ("tools/list returned no tools" if isinstance(tools, list)
                                   else "tools/list not obtained"))
    target_domain = registrable(urlparse(target).hostname or target)
    rows = []
    for kind, items in (("tool", tools), ("prompt", prompts), ("resource", resources)):
        if isinstance(items, list):
            rows.extend(_grade_items(kind, items, target_domain))
    return rows or excluded("tools/list held no tool objects")


def text_lines(rows):
    out = []
    for r in rows:
        if r["status"] == "FLAGGED":
            out.append("  %s %s %s %s %s@%d %r [%s] basis: %s" % (
                r["status"], r["test_id"], r.get("kind", "tool"), r["tool"], r["field"], r["offset"],
                r["substring"], r["severity"], r["severity_basis"]))
        elif r["status"] == "CLEAN":
            out.append("  CLEAN %s %s" % (r.get("kind", "tool"), r["tool"]))
        else:
            out.append("  EXCLUDED %s" % r.get("limitation"))
    return out
