"""Single-use challenge registry and concurrent replay tests."""

from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from mcp_authscan import challenge_registry as r


TARGET = "https://example.invalid/mcp"
DEPLOYMENT = "deployment-001"
DIGEST = "a" * 64


def create(tmp_path):
    path = str(tmp_path / "challenges.sqlite3")

    record = r.issue(path, TARGET, DEPLOYMENT)

    return path, record


def consume(path, record, **overrides):
    values = {
        "challenge": record["challenge"],
        "target": TARGET,
        "deployment_id": DEPLOYMENT,
        "report_digest": DIGEST,
        "assessment_started_at": record["issued_at"],
    }

    values.update(overrides)

    return r.consume(path, **values)


def test_single_use(tmp_path):
    path, record = create(tmp_path)

    assert consume(path, record) is True
    assert consume(path, record) is False


def test_replay_with_different_report(tmp_path):
    path, record = create(tmp_path)

    assert consume(path, record) is True

    assert consume(
        path,
        record,
        report_digest="b" * 64,
    ) is False


def test_unknown_challenge(tmp_path):
    path, record = create(tmp_path)

    assert consume(
        path,
        record,
        challenge="f" * 64,
    ) is False


def test_wrong_target(tmp_path):
    path, record = create(tmp_path)

    assert consume(
        path,
        record,
        target="https://other.invalid/mcp",
    ) is False

    assert consume(path, record) is True


def test_wrong_deployment(tmp_path):
    path, record = create(tmp_path)

    assert consume(
        path,
        record,
        deployment_id="deployment-002",
    ) is False

    assert consume(path, record) is True


def test_expired_challenge(tmp_path, monkeypatch):
    path, record = create(tmp_path)

    monkeypatch.setattr(
        r.time,
        "time",
        lambda: record["expires_at"],
    )

    assert consume(path, record) is False


def test_preissued_assessment(tmp_path):
    path, record = create(tmp_path)

    assert consume(
        path,
        record,
        assessment_started_at=record["issued_at"] - 1,
    ) is False

    assert consume(path, record) is True


def test_assessment_after_expiration(tmp_path):
    path, record = create(tmp_path)

    assert consume(
        path,
        record,
        assessment_started_at=record["expires_at"],
    ) is False


def test_clock_rollback(tmp_path, monkeypatch):
    path, record = create(tmp_path)

    monkeypatch.setattr(
        r.time,
        "time",
        lambda: record["issued_at"] - 1,
    )

    assert consume(path, record) is False


def test_unique_challenges(tmp_path):
    path = str(tmp_path / "challenges.sqlite3")

    records = [
        r.issue(path, TARGET, DEPLOYMENT)
        for _ in range(100)
    ]

    assert len({
        record["challenge"] for record in records
    }) == 100


@pytest.mark.parametrize(
    "ttl",
    [True, False, 0, -1, 86401, "900", None],
)
def test_invalid_lifetime(tmp_path, ttl):
    path = str(tmp_path / "challenges.sqlite3")

    with pytest.raises(r.ChallengeError):
        r.issue(path, TARGET, DEPLOYMENT, ttl=ttl)


@pytest.mark.parametrize(
    "digest",
    ["", "invalid", None, "A" * 64],
)
def test_invalid_report_digest(tmp_path, digest):
    path, record = create(tmp_path)

    with pytest.raises(r.ChallengeError):
        consume(path, record, report_digest=digest)

    assert consume(path, record) is True


def test_concurrent_replay(tmp_path):
    path, record = create(tmp_path)

    workers = 32
    barrier = threading.Barrier(workers)

    def attempt(index):
        barrier.wait(timeout=30)

        return consume(
            path,
            record,
            report_digest=f"{index:064x}",
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))

    accepted = sum(results)
    rejected = workers - accepted

    print(
        f"\n[REPLAY TEST] Attempts={workers} "
        f"Accepted={accepted} Rejected={rejected}"
    )

    assert accepted == 1
    assert rejected == 31


def test_persistent_consumption(tmp_path):
    path, record = create(tmp_path)

    assert consume(path, record) is True

    with r._connect(path) as db:
        row = db.execute(
            """
            SELECT consumed_at, report_digest
            FROM deployment_challenges
            WHERE challenge = ?
            """,
            (record["challenge"],),
        ).fetchone()

    assert row[0] is not None
    assert row[1] == DIGEST

    assert consume(path, record) is False
