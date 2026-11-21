from mcp_authscan.releases import MANIFEST_HASHES, manifest_for


def test_each_pinned_hash_is_sha256_hex():
    assert MANIFEST_HASHES
    for v, h in MANIFEST_HASHES.items():
        assert len(h) == 64
        assert h == h.lower()
        assert all(c in '0123456789abcdef' for c in h)


def test_latest_release_is_pinned():
    assert manifest_for('1.1.33')
