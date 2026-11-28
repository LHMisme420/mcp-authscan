"""Audit and generate page pricing strings from pricing/pricing.json (the single source).

    python tools/pricing_strings.py [ROOT]

Prints every place a tier price, tier name or retest is stated in the site and docs, whether it
agrees with pricing.json, every conflict, and the canonical strings to generate the page from.
Read only: it edits nothing. Exits 1 while a conflict or an unconfirmed field remains.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
SRC = json.loads((ROOT / "pricing" / "pricing.json").read_text(encoding="utf-8"))
T = SRC["tiers"]
FILES = ["README.md", "client/index.html", "shared/siteMetadata.ts", "shared/writtenScope.ts",
         "shared/assessmentInquiry.ts", "client/src/Landing.tsx", "client/src/assessmentForm.ts",
         "client/src/AssessmentSections.tsx", "client/src/PricingTiers.tsx", "client/src/SampleReport.tsx"]
PRICE = re.compile(r"\$?(1,?750|3,?500)(?: dollars)?")
RETEST = re.compile(r"(?i)retest")
CLAIM = re.compile(r"(?i)one (remediation )?retest|retest of the same")
SINGLE = re.compile(r"(?i)single|one server|one mcp server|1,?750")
FULL = re.compile(r"(?i)full assessment|expanded|fleet|3,?500|comprehensive")


def classify(line, at):
    """Which tier a retest claim attaches to: the nearest tier marker before the claim."""
    s = [m.start() for m in SINGLE.finditer(line) if m.start() < at]
    f = [m.start() for m in FULL.finditer(line) if m.start() < at]
    if not s and not f:
        return "no tier named (reads as every assessment)"
    if f and (not s or max(f) > max(s)):
        return "retest attached to the full tier"
    return "retest INCLUDED with the single server"


def money(n):
    return "${:,}".format(n)


def canonical():
    s, f = T["single"], T["full"]
    retest_single = {True: " including one retest", False: "", None: " [RETEST UNCONFIRMED]"}[s["includes_retest"]]
    return {
        "single.name": s["name"], "full.name": f["name"],
        "single.price": money(s["price_usd"]), "full.price": money(f["price_usd"]),
        "single.buy_label": "Pay for the %s — %s" % (s["name"].lower(), money(s["price_usd"])),
        "full.buy_label": "Pay for the %s — %s" % (f["name"].lower(), money(f["price_usd"])),
        "summary": "%s %s%s; %s %s including one retest." % (
            s["name"], money(s["price_usd"]), retest_single, f["name"].lower(), money(f["price_usd"])),
        "single.checkout": s["checkout"], "full.checkout": f["checkout"],
    }


def main():
    conflicts, retest_single = [], []
    print("== Every price / retest statement ==")
    for rel in FILES:
        p = ROOT / rel
        if not p.exists():
            print("%s: MISSING (not in this checkout)" % rel)
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            prices = {int(m.group(1).replace(",", "")) for m in PRICE.finditer(line)}
            if not prices and not RETEST.search(line):
                continue
            text = " ".join(line.split())[:220]
            bad = prices - {T["single"]["price_usd"], T["full"]["price_usd"]}
            flag = "PRICE NOT IN pricing.json" if bad else "ok"
            if bad:
                conflicts.append((rel, n, text))
            claim = CLAIM.search(line)
            if claim:
                retest_single.append((rel, n, classify(line, claim.start()), text))
            print("%s:%d [%s] %s" % (rel, n, flag, text))
    print("\n== Retest claims: which tier each attaches to ==")
    for rel, n, claim, text in retest_single:
        print("%s:%d  %s\n    %s" % (rel, n, claim, text))
    claims = {c for _, _, c, _ in retest_single}
    if "retest INCLUDED with the single server" in claims and any("full tier" in c for c in claims):
        print("CONFLICT: the site states both. Authoritative source is the Stripe line item at %s; "
              "pricing.json leaves includes_retest null until it is confirmed." % T["single"]["checkout"])
    print("\n== Canonical page strings (generated from pricing/pricing.json) ==")
    for k, v in canonical().items():
        print("%-18s %s" % (k, v))
    open_q = [t["open_question"] for t in T.values() if t.get("open_question")]
    for q in open_q:
        print("OPEN: " + q)
    return 1 if conflicts or open_q or len(claims) > 1 else 0


if __name__ == "__main__":
    sys.exit(main())
