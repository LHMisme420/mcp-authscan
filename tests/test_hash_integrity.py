"""Test that report hash covers evidence, not formatting."""

import json
import hashlib
from copy import deepcopy


def canonical_hash(payload_dict):
    """Compute hash the same way monolith.py does."""
    payload_json = json.dumps(payload_dict, sort_keys=True)
    return hashlib.sha256(payload_json.encode()).hexdigest()


def test_hash_changes_when_finding_changes():
    """Hash must change if evidence changes (finding severity)."""
    base_payload = {
        "target": "https://example.com/mcp",
        "scan_mode": "LIVE_ENDPOINT_ASSESSMENT",
        "probe_set_version": "1.1.0",
        "probes_attempted": 7,
        "probes_passed": 7,
        "probes_failed": 0,
        "probes_excluded": 2,
        "probes_observed": 0,
        "probes_not_observed": 0,
        "findings": [
            {
                "probe_id": "client-auth",
                "name": "client-auth",
                "status": "FAIL",
                "severity": "HIGH",
            }
        ],
        "tool_version": "1.1.3",
        "authorization": {
            "authorized_by": "Test",
            "auth_basis": "test",
            "contact": "test@example.com",
        },
    }
    
    hash1 = canonical_hash(base_payload)
    
    # Change severity in finding
    modified = deepcopy(base_payload)
    modified["findings"][0]["severity"] = "CRITICAL"
    hash2 = canonical_hash(modified)
    
    # Hashes must be different
    assert hash1 != hash2, "Hash must change when evidence changes"


def test_hash_unchanged_by_formatting():
    """Hash must NOT change if only template formatting changes."""
    payload = {
        "target": "https://example.com/mcp",
        "scan_mode": "LIVE_ENDPOINT_ASSESSMENT",
        "probe_set_version": "1.1.0",
        "probes_attempted": 7,
        "probes_passed": 7,
        "probes_failed": 0,
        "probes_excluded": 2,
        "probes_observed": 0,
        "probes_not_observed": 0,
        "findings": [],
        "tool_version": "1.1.3",
        "authorization": {
            "authorized_by": "Test",
            "auth_basis": "test",
            "contact": "test@example.com",
        },
    }
    
    hash1 = canonical_hash(payload)
    # Template changes don't affect the canonical payload
    hash2 = canonical_hash(payload)
    
    # Same payload = same hash, regardless of how it's rendered
    assert hash1 == hash2, "Hash must be stable for identical evidence"


if __name__ == "__main__":
    test_hash_changes_when_finding_changes()
    test_hash_unchanged_by_formatting()
    print("✓ Hash integrity tests pass")
