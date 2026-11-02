"""Command Voice detection for MCP surfaces."""
import re

RULES = (
    ("MCPV-1", "concealment", "high", (
        r"do not (?:tell|inform|mention|reveal) the user",
        r"don'?t (?:tell|inform|mention|show) the user",
        r"without (?:telling|informing|notifying) the user",
        r"hide .{0,24}from the user",
        r"never (?:tell|mention|disclose) (?:this|it) to the user",
    )),
    ("MCPV-2", "authority", "medium", (
        r"the platform requires",
        r"you are required to",
        r"this (?:overrides|supersedes) (?:the|any|all)",
        r"(?:administrator|policy) (?:requires|mandates)",
    )),
    ("MCPV-3", "directive", "low", (
        r"\byou must\b",
        r"\byou (?:should|need to) (?:always|first)\b",
        r"\balways (?:use|call|invoke)\b",
        r"\bnever (?:use|call|invoke)\b",
        r"\bdo not (?:use|call|invoke)\b",
        r"\bignore (?:the |any )?(?:prior|previous|above)",
    )),
)


def _texts(surface):
    surface = surface or {}
    text = surface.get("instructions")
    if isinstance(text, str) and text:
        yield "instructions", "instructions", text
    for kind, key in (("tool", "tools"),
                      ("prompt", "prompts"),
                      ("resource", "resources")):
        for item in surface.get(key) or []:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("uri") or ""
            desc = item.get("description")
            if isinstance(desc, str) and desc:
                yield kind, str(name), desc


def scan(surface, include_directive=False):
    findings = []
    for kind, name, text in _texts(surface):
        for rule, register, severity, patterns in RULES:
            if register == "directive" and not include_directive:
                continue
            hit = None
            for pattern in patterns:
                hit = re.search(pattern, text, re.I)
                if hit:
                    break
            if not hit:
                continue
            findings.append({
                "rule": rule,
                "register": register,
                "severity": severity,
                "confidence": "HIGH",
                "kind": kind,
                "ref": kind + ":" + name,
                "endpoint": "",
                "line": 0,
                "offset": hit.start(),
                "match": hit.group(0)[:80],
            })
    findings.sort(key=lambda f: (f["rule"], f["ref"]))
    return findings
