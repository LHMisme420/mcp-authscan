"""Endpoint-study sentences, generated from data/endpoint_studies.json (the dataset registry).

    python tools/endpoint_studies.py            # print sentences and every unsourced field
    python tools/endpoint_studies.py --write    # rewrite the generated block in README.md
    python tools/endpoint_studies.py --check    # exit 1 if README.md's block is stale

Every count is printed in the same sentence as its study id and date. A study with no
sourced counts produces no sentence.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REG = json.loads((ROOT / "data" / "endpoint_studies.json").read_text(encoding="utf-8"))
START, END = "<!-- endpoint-studies:start -->", "<!-- endpoint-studies:end -->"


def sentence(s):
    if s["endpoints"] is None or s["speak_mcp"] is None:
        return None
    walk = "registry walk %s, finished %s" % (s["registry_walk"], s["walk_finished"]) if s["registry_walk"] and s["walk_finished"] \
        else "walk and walk date not recorded"
    pct = s["figures"].get("no_credential_handshake_pct_of_speak_mcp")
    tail = ", %s%% of the %s that speak MCP completed a handshake with no credential" % (pct, format(s["speak_mcp"], ",")) \
        if pct is not None else ", %s speak MCP" % format(s["speak_mcp"], ",")
    return "Study %s (dated %s by %s; %s): %s registry endpoints walked%s." % (
        s["id"], s["dated"], s["dated_by"], walk, format(s["endpoints"], ","), tail)


def block():
    lines = [x for x in (sentence(s) for s in REG["studies"]) if x]
    return "\n".join([START, "\n\n".join("Against the field: " + l for l in lines), END])


FORBIDDEN = ("16585", "16,585")  # never in anything a buyer can read


def published_texts():
    """Everything a buyer can read: README (the PyPI page), both package descriptions, site strings."""
    import tomllib
    out = {"README.md": (ROOT / "README.md").read_text(encoding="utf-8")}
    for rel in ("pyproject.toml", "mcp_authscan/pyproject.toml"):
        out[rel + ":description"] = tomllib.loads((ROOT / rel).read_text(encoding="utf-8"))["project"]["description"]
    for pat in ("client/index.html", "client/src/*.tsx", "client/src/*.ts", "shared/*.ts"):
        for f in sorted(ROOT.glob(pat)):
            if ".test." not in f.name:
                out[str(f.relative_to(ROOT))] = f.read_text(encoding="utf-8")
    return out


def _forms(v):
    if isinstance(v, float):
        return ["%s%%" % v]
    return [str(v), format(v, ",")]


def violations(texts):
    """(where, count, study id) for each recorded count printed without its study id in the paragraph."""
    bad = []
    for s in REG["studies"]:
        values = [v for v in (s["endpoints"], s["speak_mcp"], *s["figures"].values()) if v is not None]
        for where, text in texts.items():
            for para in re.split(r"\n\s*\n", text):
                for v in values:
                    for form in _forms(v):
                        if re.search(r"(?<![\d,.])%s(?![\d,])" % re.escape(form), para) and s["id"] not in para:
                            bad.append((where, form, s["id"]))
    return bad


def forbidden(texts):
    return [(where, f) for where, text in texts.items() for f in FORBIDDEN if f in text]


def gaps():
    out = []
    for s in REG["studies"]:
        for k in ("registry_walk", "walk_finished", "dated", "endpoints", "speak_mcp"):
            if s[k] in ("", None):
                out.append("%s: %s not sourced" % (s["id"], k))
    return out


def main(argv):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    cur = re.search(re.escape(START) + r".*?" + re.escape(END), readme, re.S)
    if "--write" in argv:
        new = readme.replace(cur.group(0), block()) if cur else readme
        (ROOT / "README.md").write_text(new, encoding="utf-8")
        print("README.md block written" if cur else "README.md has no generated block; add the markers first")
        return 0 if cur else 1
    if "--check" in argv:
        ok = bool(cur) and cur.group(0) == block()
        print("README.md block current" if ok else "README.md block stale or missing")
        return 0 if ok else 1
    print(block())
    for g in gaps():
        print("GAP " + g)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
