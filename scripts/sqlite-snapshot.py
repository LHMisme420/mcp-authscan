#!/usr/bin/env python3
"""Private SQLite backup helper. Never prints database contents."""
import hashlib
import os
from pathlib import Path
import sqlite3
import sys


def validate(connection):
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ValueError("SQLite integrity check failed")
    tables = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    if not {"organizations", "findings"}.issubset(tables):
        raise ValueError("Not a VATA findings database")
    # Include every table, including legacy scan_history and ownership metadata.
    digest = hashlib.sha256()
    for line in connection.iterdump():
        digest.update(line.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def main():
    operation, source, *rest = sys.argv[1:]
    uri = Path(source).resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=15) as connection:
        if operation == "check":
            print(validate(connection))
        elif operation == "snapshot":
            destination = rest[0]
            fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with sqlite3.connect(destination) as backup:
                connection.backup(backup)
                print(validate(backup))
        else:
            raise ValueError("Unknown snapshot operation")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("SQLite snapshot validation failed; original data was not replaced.", file=sys.stderr)
        sys.exit(1)
