"""Print one version's section of a Keep-a-Changelog file, without its heading.

Usage: python3 scripts/changelog_section.py VERSION [CHANGELOG.md]

Exits non-zero, printing nothing to stdout, when the version has no section
or its section is empty, so a release is never given blank notes.
"""

import re
import sys


def section(text: str, version: str) -> str:
    heading = re.compile(r"^## \[" + re.escape(version) + r"\](?:\s|$)")
    lines, out, inside = text.splitlines(), [], False
    for line in lines:
        if inside:
            if line.startswith("## "):
                break
            out.append(line)
        elif heading.match(line):
            inside = True
    if not inside:
        raise LookupError(f"no CHANGELOG section for {version}")
    body = "\n".join(out).strip()
    if not body:
        raise LookupError(f"CHANGELOG section for {version} is empty")
    return body + "\n"


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    path = argv[2] if len(argv) == 3 else "CHANGELOG.md"
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        sys.stdout.write(section(text, argv[1]))
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
