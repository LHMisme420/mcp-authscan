import pytest


@pytest.fixture(autouse=True)
def _reset_module_flags():
    import mcp_authscan.monolith as _m
    import mcp_authscan.oauth_probes_v2 as _p
    _m.ALLOW_PRIVATE_TARGETS = False
    _p.ALLOW_PRIVATE_TARGETS = False
    yield
