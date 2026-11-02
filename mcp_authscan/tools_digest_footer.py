"""Footer sentence for the tools/list digest, shared by the text and HTML reports."""


def footer_line(payload):
    """One plain sentence about the digest for a report footer."""
    d = (payload or {}).get("tools_digest") or {}
    if not d:
        return "Tools digest: not recorded for this run."
    if d.get("captured"):
        return ("Tools digest: one tools/list after initialize with the session header carried, %s tools, "
                "digest %s. Outside the hash; it records what this session received, not a verdict." %
                (d.get("tool_count"), d.get("digest")))
    reason = d.get("reason") or "reason not recorded"
    return "Tools digest: not captured (%s). No effect on verdicts or coverage." % reason
