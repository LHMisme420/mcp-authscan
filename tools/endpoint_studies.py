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


def _num(f):
    v = f["value"]
    return "%s%%" % v if f.get("unit") == "%" else format(v, ",")


def sentence(s):
    if s.get("endpoints") is None:
        return None
    parts = []
    for f in s["figures"]:
        t = "%s %s" % (_num(f), f["text"])
        if f.get("pct") is not None:
            t += " (%s%%)" % f["pct"]
        parts.append(t)
    walk = "registry walk %s, finished %s" % (s["registry_walk"], s["walk_finished"]) \
        if s["registry_walk"] and s["walk_finished"] else "walk and walk date not recorded"
    return "Study %s (published %s, %s; %s; %s): %s endpoints; %s." % (
        s["id"], s["dated"], s["dated_by"], s["method"], walk, format(s["endpoints"], ","), "; ".join(parts))


def block():
    lines = [x for x in (sentence(s) for s in REG["studies"]) if x]
    return "\n".join([START, "\n\n".join("Against the field: " + l for l in lines), END])


FORBIDDEN = ("16585", "16,585",  # never in anything a buyer can read
             "63.1%", "13.1%")  # a different cut of the census than its post (61.3/15.4); publish only once recorded as a labelled later read


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


MIN_DISTINCT = 1000  # smaller bare integers (23, 447, 501) are not identifiable on their own; checked via their study sentence


def _checked_forms(s):
    forms = [str(s["endpoints"]), format(s["endpoints"], ",")] if s.get("endpoints") else []
    for f in s["figures"]:
        if f.get("unit") == "%":
            forms.append("%s%%" % f["value"])
        elif f["value"] >= MIN_DISTINCT:
            forms += [str(f["value"]), format(f["value"], ",")]
        if f.get("pct") is not None:
            forms.append("%s%%" % f["pct"])
    return forms


def violations(texts):
    """(where, count, study id) for each recorded count printed without its study id in the paragraph."""
    bad = []
    for s in REG["studies"]:
        for where, text in texts.items():
            for para in re.split(r"\n\s*\n", text):
                for form in _checked_forms(s):
                    if re.search(r"(?<![\d,.])%s(?![\d,])" % re.escape(form), para) and s["id"] not in para:
                        bad.append((where, form, s["id"]))
    return bad


def forbidden(texts):
    return [(where, f) for where, text in texts.items() for f in FORBIDDEN if f in text]


def gaps():
    out = []
    for s in REG["studies"]:
        for k in ("registry_walk", "walk_finished", "dated", "endpoints"):
            if s[k] in ("", None):
                why = s.get("registry_walk_empty_because") if k == "registry_walk" else s.get("pending")
                out.append("%s: %s not sourced%s" % (s["id"], k, (" (" + why + ")") if why else ""))
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
