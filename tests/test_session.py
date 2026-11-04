import pytest
from types import SimpleNamespace
from mcp_authscan.monolith import EgressRefusalError
from mcp_authscan.session import MCPClientSession, REFUSAL_NOT_INITIALIZED

def make(replies, header="", seen=None):
    box = []

    def request(method, params):
        box.append(method)
        value = replies.get(method)
        if isinstance(value, Exception):
            raise value
        return value

    def connect(hosts):
        if seen is not None:
            seen.append(hosts)
        return SimpleNamespace(request=request, session_header=header, calls=box, closed=False)

    return connect, box

def test_one_handshake():
    replies = {"initialize": {"protocolVersion": "v1", "capabilities": {}}, "tools/list": {"tools": []}, "prompts/list": {"prompts": []}}
    connect, box = make(replies)
    session = MCPClientSession("host1", ["host1"], connect)
    assert session.initialize().ok is True
    assert session.tools_list().ok is True
    assert session.prompts_list().ok is True
    assert session.attempts == 1
    assert box == ["initialize", "tools/list", "prompts/list"]

def test_header_carried():
    connect, box = make({"initialize": {"protocolVersion": "v1", "capabilities": {"resources": {}}}}, header="sess1")
    session = MCPClientSession("host1", ["host1"], connect)
    result = session.initialize()
    assert result.session_header == "sess1"
    assert result.capabilities == {"resources": {}}

def test_allowed_hosts_reach_connect():
    seen = []
    connect, box = make({"initialize": {"protocolVersion": "v1"}}, seen=seen)
    session = MCPClientSession("host1", ["host1", "host2"], connect)
    session.initialize()
    assert seen == [("host1", "host2")]

def test_call_before_initialize_refused():
    connect, box = make({})
    session = MCPClientSession("host1", ["host1"], connect)
    result = session.tools_list()
    assert result.ok is False
    assert result.reason == REFUSAL_NOT_INITIALIZED
    assert box == []

def test_refusal_on_connect_reraised():
    def connect(hosts):
        raise EgressRefusalError("refused")
    session = MCPClientSession("host1", ["host1"], connect)
    with pytest.raises(EgressRefusalError):
        session.initialize()

def test_failed_connect_blocks_calls():
    def connect(hosts):
        raise ValueError("dead")
    session = MCPClientSession("host1", ["host1"], connect)
    result = session.initialize()
    assert result.ok is False
    assert result.reason.startswith("connect failed: ValueError")
    later = session.resources_list()
    assert later.ok is False
    assert later.reason.startswith("session not established")
