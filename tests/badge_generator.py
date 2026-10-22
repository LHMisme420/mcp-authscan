#!/usr/bin/env python3
"""
Generate SVG badges for benchmark scores (Precision, Recall, F1).
Used in CI to create visual proof of detector quality.

Usage:
    python3 tests/badge_generator.py --report vata-authscan-bench.json --output badges/
"""
import argparse
import json
import sys
from pathlib import Path


def color_for_score(score):
    """Return color based on score: green (>0.95), yellow (>0.80), red (<0.80)."""
    if score >= 0.95:
        return "#2cba4e"  # green
    elif score >= 0.80:
        return "#dfb317"  # yellow
    else:
        return "#e05d44"  # red


def generate_badge(label, value, color="#555", filename="badge.svg"):
    """Generate a simple SVG badge."""
    score_str = f"{float(value):.2f}"
    label_width = len(label) * 7
    value_width = len(score_str) * 7
    total_width = label_width + value_width + 20

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{total_width}" height="20" role="img" aria-label="{label}: {score_str}">
    <title>{label}: {score_str}</title>
    <linearGradient id="s" x2="0" y2="100%">
        <stop offset="0" stop-color="#bbb"/>
        <stop offset="1" stop-color="#999"/>
    </linearGradient>
    <clipPath id="r">
        <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
    </clipPath>
    <g clip-path="url(#r)">
        <rect width="{label_width + 10}" height="20" fill="#555"/>
        <rect x="{label_width + 10}" width="{value_width + 10}" height="20" fill="{color}"/>
        <rect width="{total_width}" height="20" fill="url(#s)"/>
    </g>
    <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
        <text aria-hidden="true" x="{(label_width + 10) // 2}" y="15" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(label_width) * 10}">{label}</text>
        <text x="{(label_width + 10) // 2}" y="14" transform="scale(.1)" fill="#fff" textLength="{(label_width) * 10}">{label}</text>
        <text aria-hidden="true" x="{label_width + 10 + (value_width + 10) // 2}" y="15" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(value_width) * 10}">{score_str}</text>
        <text x="{label_width + 10 + (value_width + 10) // 2}" y="14" transform="scale(.1)" fill="#fff" textLength="{(value_width) * 10}">{score_str}</text>
    </g>
</svg>"""
    Path(filename).parent.mkdir(parents=True, exist_ok=True)
    Path(filename).write_text(svg)
    return filename


def main():
    ap = argparse.ArgumentParser(description="Generate benchmark score badges")
    ap.add_argument("--report", required=True, help="path to benchmark JSON report")
    ap.add_argument("--output", default="badges", help="output directory for badges")
    args = ap.parse_args()

    try:
        report = json.loads(Path(args.report).read_text())
    except Exception as e:
        print(f"ERROR: failed to load report: {e}")
        return 1

    precision = report.get("precision", 0)
    recall = report.get("recall", 0)
    f1 = report.get("f1", 0)

    out_dir = Path(args.output)

    generate_badge("precision", precision, color_for_score(precision),
                  f"{out_dir}/precision-badge.svg")
    generate_badge("recall", recall, color_for_score(recall),
                  f"{out_dir}/recall-badge.svg")
    generate_badge("f1", f1, color_for_score(f1),
                  f"{out_dir}/f1-badge.svg")

    print(f"[+] Generated badges in {out_dir}")
    print(f"    precision-badge.svg  ({precision:.2f})")
    print(f"    recall-badge.svg     ({recall:.2f})")
    print(f"    f1-badge.svg         ({f1:.2f})")

    # Emit markdown reference
    print("\nMarkdown reference (add to README):")
    print(f"[![Precision]({out_dir}/precision-badge.svg)]({args.report})")
    print(f"[![Recall]({out_dir}/recall-badge.svg)]({args.report})")
    print(f"[![F1]({out_dir}/f1-badge.svg)]({args.report})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
