"""Counts and coverage derived from probe records. Nothing is stored."""
from ._common import VALID_STATUSES


class CoverageError(Exception):
    """Coverage requirement not met."""
    pass


def count_probes(records):
    """Bucket by status and derive the totals. Refuses a list it cannot trust."""
    for index, rec in enumerate(records):
        if rec is None:
            raise RuntimeError(
                "probe at index %d returned None; every probe must return a record"
                % index)
        if rec.status not in VALID_STATUSES:
            raise RuntimeError(
                "probe %s returned illegal status %r" % (rec.probe_id, rec.status))
    counts = {status: sum(1 for r in records if r.status == status)
              for status in VALID_STATUSES}
    counts["in_scope"] = len(records)
    counts["attempted"] = counts["in_scope"] - counts["EXCLUDED"]
    assert counts["attempted"] + counts["EXCLUDED"] == counts["in_scope"]
    assert sum(counts[s] for s in VALID_STATUSES) == counts["in_scope"]
    return counts


def coverage(counts):
    """Share of testable probes that reached a verdict. PASS and FAIL both count."""
    if counts["attempted"] == 0:
        raise CoverageError("zero testable probes")
    return (counts["PASS"] + counts["FAIL"]) / float(counts["attempted"])
