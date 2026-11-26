"""Transactional, single-use deployment authorization challenges."""

import argparse
import json
import secrets
import sqlite3
import time
from contextlib import closing

from mcp_authscan.assurance_freshness import valid_challenge


SCHEMA = """
CREATE TABLE IF NOT EXISTS deployment_challenges (
    challenge TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    report_digest TEXT
)
"""


class ChallengeError(ValueError):
    pass


def _connect(path):
    connection = sqlite3.connect(
        path,
        timeout=30,
        isolation_level=None,
    )

    try:
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(SCHEMA)
    except Exception:
        connection.close()
        raise

    return connection


def _identifier(value):
    return (
        isinstance(value, str)
        and bool(value.strip())
        and len(value) <= 2048
    )


def issue(path, target, deployment_id, ttl=900):
    """Issue a challenge from the trusted deployment authority."""

    if not _identifier(target):
        raise ChallengeError("Invalid target")

    if not _identifier(deployment_id):
        raise ChallengeError("Invalid deployment identifier")

    if type(ttl) is not int or not 1 <= ttl <= 86400:
        raise ChallengeError("Invalid challenge lifetime")

    challenge = secrets.token_hex(32)
    now = int(time.time())

    with closing(_connect(path)) as db:
        db.execute(
            """
            INSERT INTO deployment_challenges (
                challenge, target, deployment_id,
                issued_at, expires_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                challenge,
                target,
                deployment_id,
                now,
                now + ttl,
            ),
        )

    return {
        "challenge": challenge,
        "target": target,
        "deployment_id": deployment_id,
        "issued_at": now,
        "expires_at": now + ttl,
    }


def consume(
    path,
    challenge,
    target,
    deployment_id,
    report_digest,
    assessment_started_at,
    assessment_completed_at=None,
    max_age=None,
    max_skew=0,
):
    """Atomically consume a previously verified challenge.

    Caller must authenticate and validate the report before calling.
    """

    if not valid_challenge(challenge):
        raise ChallengeError("Invalid challenge")

    if not valid_challenge(report_digest):
        raise ChallengeError("Invalid report digest")

    if not _identifier(target):
        raise ChallengeError("Invalid target")

    if not _identifier(deployment_id):
        raise ChallengeError("Invalid deployment identifier")

    if type(assessment_started_at) is not int:
        raise ChallengeError("Invalid assessment start")

    with closing(_connect(path)) as db:
        db.execute("BEGIN IMMEDIATE")

        try:
            now = int(time.time())

            if assessment_started_at > now + max_skew:
                db.execute("ROLLBACK")
                return False

            if assessment_completed_at is not None:
                if (
                    type(assessment_completed_at) is not int
                    or assessment_completed_at < assessment_started_at
                    or assessment_completed_at > now + max_skew
                ):
                    db.execute("ROLLBACK")
                    return False

            if max_age is not None:
                if (
                    type(max_age) is not int
                    or max_age <= 0
                    or now - assessment_started_at > max_age
                ):
                    db.execute("ROLLBACK")
                    return False

            cursor = db.execute(
                """
                UPDATE deployment_challenges
                SET consumed_at = ?, report_digest = ?
                WHERE challenge = ?
                  AND target = ?
                  AND deployment_id = ?
                  AND consumed_at IS NULL
                  AND issued_at <= ?
                  AND expires_at > ?
                  AND issued_at <= ?
                  AND expires_at > ?
                """,
                (
                    now,
                    report_digest,
                    challenge,
                    target,
                    deployment_id,
                    now,
                    now,
                    assessment_started_at,
                    assessment_started_at,
                ),
            )

            accepted = cursor.rowcount == 1

            db.execute("COMMIT")

            return accepted

        except Exception:
            db.execute("ROLLBACK")
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Issue deployment authorization challenges"
    )

    parser.add_argument("database")
    parser.add_argument("--target", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--ttl", type=int, default=900)

    args = parser.parse_args(argv)

    try:
        result = issue(
            args.database,
            args.target,
            args.deployment_id,
            args.ttl,
        )
    except Exception as exc:
        print(json.dumps({
            "status": "ERROR",
            "reason": type(exc).__name__,
        }))
        return 1

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
