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
    # NOT_IMPLEMENTED probes are never sent: neither attempted nor excluded.
    counts["attempted"] = counts["in_scope"] - counts["EXCLUDED"] - counts["NOT_IMPLEMENTED"]
    assert counts["attempted"] + counts["EXCLUDED"] + counts["NOT_IMPLEMENTED"] == counts["in_scope"]
    assert sum(counts[s] for s in VALID_STATUSES) == counts["in_scope"]
    return counts


def testable(counts):
    """Probes that could be tested: the declared set less the EXCLUDED ones (prerequisite missing)."""
    return counts["in_scope"] - counts["EXCLUDED"]


def coverage(counts):
    """Share of the testable probes (in_scope - EXCLUDED) that reached a verdict. PASS and FAIL both count.

    The single source for the JSON coverage field and the printed Coverage line. Raises
    CoverageError when nothing was testable; the caller routes that to exit 5, never to 0.
    """
    if counts["attempted"] == 0 or testable(counts) <= 0:
        raise CoverageError("zero testable probes")
    return (counts["PASS"] + counts["FAIL"]) / float(testable(counts))
