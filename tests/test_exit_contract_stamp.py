from mcp_authscan import monolith


def test_exit_contract_stamp_is_pinned():
    assert monolith.EXIT_CONTRACT == "2026.11.02.4"
