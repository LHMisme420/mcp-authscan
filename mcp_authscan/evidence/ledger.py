"""boundary-ledger-v1: append-only chain of states for one target at one access class.

Specification: schemas/boundary-ledger-v1.md

Line 1 is a header {schema, target, access_class}. Every later line is a row:
a security-state-v1 object (content keys + state_id + previous_state_id)
plus a ``record``:

    "record": {
      "report_hash": "<64 hex>",          # the graded report this row was produced with
      "observed_at": {"start": ..., "end": ...},
      "attestation": {"alg": "ed25519", "key_id": ..., "value": ...} | null
    }

``record`` is never part of the STATE ID. ``attestation`` is an Ed25519
signature over row_statement(): target, access_class, state_id,
previous_state_id, report_hash and observed_at. A row is therefore checkable
on its own, even if its report is lost. A null attestation marks an
unsigned row; it is structurally valid but can never satisfy a delta.

Appends are serialized (exclusive flock on <ledger>.lock) and crash-safe
(whole file written to a temp file, fsynced, renamed). open_ledger /
commit_all give an all-or-nothing append across several ledgers.
"""
import base64
import json
import os

from .observation import verify_observation
from .state import ACCESS_CLASSES, CONTENT_KEYS, compute_state_id, normalize_target, validate_state

SCHEMA = "boundary-ledger-v1"
ROW_STATEMENT_SCHEMA = "boundary-ledger-row-v1"
SIGNED = "SIGNED"
UNSIGNED = "UNSIGNED"
INVALID = "SIGNATURE INVALID"
UNKNOWN_KEY = "UNKNOWN KEY"


def _dump(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n"


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def make_header(target: str, access_class: str) -> dict:
    if normalize_target(target) != target:
        raise ValueError(f"target: must be normalized, got {target!r}")
    if access_class not in ACCESS_CLASSES:
        raise ValueError(f"access_class: must be one of {', '.join(ACCESS_CLASSES)}")
    return {"schema": SCHEMA, "target": target, "access_class": access_class}


def row_statement(header: dict, row: dict) -> bytes:
    """The exact bytes a row attestation signs."""
    record = row["record"]
    return _canonical({
        "schema": ROW_STATEMENT_SCHEMA,
        "target": header["target"],
        "access_class": header["access_class"],
        "state_id": row["state_id"],
        "previous_state_id": row["previous_state_id"],
        "report_hash": record["report_hash"],
        "observed_at": record["observed_at"],
    })


def _check_record(n, record):
    where = n if isinstance(n, str) else f"line {n}"
    if not isinstance(record, dict) or sorted(record) != ["attestation", "observed_at", "report_hash"]:
        raise ValueError(f"{where}: record must be {{report_hash, observed_at, attestation}}")
    if not _is_hex64(record["report_hash"]):
        raise ValueError(f"{where}: record.report_hash must be 64 lowercase hex characters")
    observed = record["observed_at"]
    if not isinstance(observed, dict) or sorted(observed) != ["end", "start"] or not all(
            isinstance(v, str) for v in observed.values()):
        raise ValueError(f"{where}: record.observed_at must be {{start, end}}")
    att = record["attestation"]
    if att is not None and (not isinstance(att, dict) or sorted(att) != ["alg", "key_id", "value"]
                            or att["alg"] != "ed25519" or not _is_hex64(att["key_id"])
                            or not isinstance(att["value"], str)):
        raise ValueError(f"{where}: record.attestation must be null or {{alg: ed25519, key_id, value}}")


def attestation_status(header: dict, row: dict, keys) -> str:
    """SIGNED, UNSIGNED, UNKNOWN KEY or SIGNATURE INVALID for one row.

    ``keys`` is a list of published keys {key_id, alg: ed25519, public_key:
    unpadded base64url of the 32 raw bytes}, the /keys.json format.
    """
    att = row["record"]["attestation"]
    if att is None:
        return UNSIGNED
    entry = next((k for k in keys or [] if k.get("key_id") == att["key_id"] and k.get("alg") == "ed25519"), None)
    if entry is None:
        return UNKNOWN_KEY
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw = base64.urlsafe_b64decode(entry["public_key"] + "=" * (-len(entry["public_key"]) % 4))
        sig = base64.urlsafe_b64decode(att["value"] + "=" * (-len(att["value"]) % 4))
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, row_statement(header, row))
    except (InvalidSignature, ValueError, TypeError):
        return INVALID
    return SIGNED


def verify_ledger(lines: list, keys=None) -> str | None:
    """Verify parsed ledger lines (header first); return the head STATE ID.

    Structural checks always. With ``keys``, every non-null attestation must
    verify against a listed key. Raises ValueError naming the line.
    """
    if not lines:
        raise ValueError("line 1: missing header")
    header = lines[0]
    if not isinstance(header, dict) or sorted(header) != ["access_class", "schema", "target"]:
        raise ValueError("line 1: header must be {schema, target, access_class}")
    if header["schema"] != SCHEMA:
        raise ValueError(f"line 1: schema must be {SCHEMA!r}")
    try:
        make_header(header["target"], header["access_class"])
    except ValueError as e:
        raise ValueError(f"line 1: {e}") from None
    prev_id = None
    for n, row in enumerate(lines[1:], start=2):
        if not isinstance(row, dict) or "record" not in row:
            raise ValueError(f"line {n}: rows must carry a record")
        _check_record(n, row["record"])
        try:
            validate_state(row_state(row))
        except ValueError as e:
            raise ValueError(f"line {n}: {e}") from None
        if "state_id" not in row or "previous_state_id" not in row:
            raise ValueError(f"line {n}: rows must carry state_id and previous_state_id")
        if row["previous_state_id"] != prev_id:
            raise ValueError(f"line {n}: previous_state_id breaks the chain")
        if row["state_id"] == prev_id:
            raise ValueError(f"line {n}: no-op append (same state as line {n - 1})")
        if row["access_class"] != header["access_class"]:
            raise ValueError(f"line {n}: access_class differs from the ledger's")
        if keys is not None and row["record"]["attestation"] is not None:
            status = attestation_status(header, row, keys)
            if status != SIGNED:
                raise ValueError(f"line {n}: attestation {status}")
        prev_id = row["state_id"]
    return prev_id


def verify_row(header: dict, row: dict, keys) -> str:
    """Verify one row on its own (no chain): structure, STATE ID, class, attestation.

    Returns the attestation status (SIGNED, UNSIGNED, UNKNOWN KEY, SIGNATURE
    INVALID); raises ValueError if the row is malformed. This is what lets a
    row travel outside its ledger, e.g. inline in a report.
    """
    make_header(header["target"], header["access_class"])
    if not isinstance(row, dict) or "record" not in row:
        raise ValueError("row: must carry a record")
    _check_record("row", row["record"])
    validate_state(row_state(row))
    if "state_id" not in row or "previous_state_id" not in row:
        raise ValueError("row: must carry state_id and previous_state_id")
    if row["access_class"] != header["access_class"]:
        raise ValueError("row: access_class differs from the header's")
    return attestation_status(header, row, keys)


def row_state(row: dict) -> dict:
    """The security-state-v1 object of a row (record removed)."""
    return {k: v for k, v in row.items() if k != "record"}


def append_entry(lines: list, observation: dict, report_hash: str, signer=None) -> dict | None:
    """Return the row to append for ``observation``, or None if it equals the head.

    ``signer(bytes) -> {alg, key_id, value}`` signs row_statement(); without
    one the row's attestation is null (unsigned). Raises ValueError if the
    observation is invalid or names a different target or access class.
    """
    head = verify_ledger(lines)
    verify_observation(observation)
    header = lines[0]
    if observation["target"] != header["target"]:
        raise ValueError(f"target: ledger is for {header['target']!r}, observation is for {observation['target']!r}")
    state = observation["state"]
    if state["access_class"] != header["access_class"]:
        raise ValueError(f"access_class: ledger is {header['access_class']!r}, "
                         f"observation is {state['access_class']!r}")
    if not _is_hex64(report_hash):
        raise ValueError("report_hash: must be 64 lowercase hex characters")
    state_id = compute_state_id(state)
    if state_id == head:
        return None
    row = {k: state[k] for k in CONTENT_KEYS}
    row["state_id"] = state_id
    row["previous_state_id"] = head
    row["record"] = {"report_hash": report_hash, "observed_at": dict(observation["observed_at"]),
                     "attestation": None}
    if signer is not None:
        row["record"]["attestation"] = signer(row_statement(header, row))
    return row


def read_ledger(path, keys=None) -> list:
    """Parse and verify a ledger file; return its lines (header first)."""
    with open(path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh.read().splitlines()]
    verify_ledger(lines, keys)
    return lines


class PendingAppend:
    """One ledger opened for an all-or-nothing append. Holds the lock until closed."""

    def __init__(self, path, observation):
        self.path = os.path.abspath(path)
        self.observation = observation
        self.row = None
        self._tmp = None
        self._lock = None
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            self._lock = open(self.path + ".lock", "a", encoding="utf-8")
            try:
                import fcntl
                fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX)
            except ImportError:  # pragma: no cover - non-POSIX: no cross-process lock
                pass
            if os.path.exists(self.path):
                self.lines = read_ledger(self.path)
                with open(self.path, encoding="utf-8") as fh:
                    self._existing = fh.read()
            else:
                self.lines = [make_header(observation["target"], observation["state"]["access_class"])]
                self._existing = _dump(self.lines[0])
            self.head = verify_ledger(self.lines)
            # Refusals (target, class, invalid observation) surface here, before anything is signed.
            append_entry(self.lines, observation, "0" * 64)
        except BaseException:
            self.close()
            raise

    @property
    def unchanged(self) -> bool:
        return self.head == compute_state_id(self.observation["state"])

    def prepare(self, report_hash, signer=None):
        self.row = append_entry(self.lines, self.observation, report_hash, signer)
        return self.row

    def _write_tmp(self):
        self._tmp = f"{self.path}.tmp.{os.getpid()}"
        with open(self._tmp, "w", encoding="utf-8") as fh:
            fh.write(self._existing + _dump(self.row))
            fh.flush()
            os.fsync(fh.fileno())

    def close(self):
        if self._tmp and os.path.exists(self._tmp):
            os.remove(self._tmp)
        self._tmp = None
        if self._lock is not None and not self._lock.closed:
            self._lock.close()


def open_ledger(path, observation) -> PendingAppend:
    """Lock and verify the ledger at ``path`` and check ``observation`` against it."""
    return PendingAppend(path, observation)


def commit_all(pending: list) -> None:
    """Write every prepared row, all or nothing, then release every lock.

    Phase 1 writes and fsyncs a temporary file per ledger; any failure
    discards them all and nothing changes. Phase 2 renames them into place.
    A rename failing after another succeeded is the only way a subset can
    land, and it raises.
    """
    try:
        changing = [p for p in pending if p.row is not None]
        for p in changing:
            p._write_tmp()
        for p in changing:
            os.replace(p._tmp, p.path)
            p._tmp = None
    finally:
        for p in pending:
            p.close()


def close_all(pending: list) -> None:
    for p in pending:
        p.close()


def append_observation(path, observation: dict, report_hash: str, signer=None) -> dict | None:
    """Append one observation's state to one ledger (locked, atomic)."""
    pending = open_ledger(path, observation)
    try:
        row = pending.prepare(report_hash, signer)
    except BaseException:
        pending.close()
        raise
    commit_all([pending])
    return row
