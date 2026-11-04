from dataclasses import dataclass, field

from .monolith import EgressRefusalError

HANDSHAKE_PROTOCOL = "2025-06-18"
REFUSAL_NOT_INITIALIZED = "session not initialized"
REFUSAL_CONNECT = "connect failed"
REFUSAL_INITIALIZE = "initialize failed"
NAME_ATTR = chr(95) + chr(95) + "name" + chr(95) + chr(95)


def err_name(exc):
    return getattr(type(exc), NAME_ATTR)


@dataclass
class Initialized:
    ok: bool = False
    reason: str = ""
    protocol_version: str = ""
    capabilities: dict = field(default_factory=dict)
    session_header: str = ""


@dataclass
class Called:
    ok: bool = False
    reason: str = ""
    payload: dict = field(default_factory=dict)


@dataclass
class MCPClientSession:
    target: str
    allowed_hosts: object
    connect: object
    transport: object = None
    result: object = None
    attempts: int = 0

    def initialize(self):
        if self.result is not None:
            return self.result
        self.attempts += 1
        self.allowed_hosts = tuple(self.allowed_hosts or ())
        try:
            self.transport = self.connect(self.allowed_hosts)
        except EgressRefusalError:
            raise
        except Exception as exc:
            self.result = Initialized(ok=False, reason=REFUSAL_CONNECT + ": " + err_name(exc))
            return self.result
        try:
            reply = self.transport.request("initialize", {"protocolVersion": HANDSHAKE_PROTOCOL})
        except EgressRefusalError:
            raise
        except Exception as exc:
            self.result = Initialized(ok=False, reason=REFUSAL_INITIALIZE + ": " + err_name(exc))
            return self.result
        if not isinstance(reply, dict):
            self.result = Initialized(ok=False, reason="initialize returned no object")
            return self.result
        self.result = Initialized(
            ok=True,
            protocol_version=reply.get("protocolVersion") or "",
            capabilities=reply.get("capabilities") or {},
            session_header=getattr(self.transport, "session_header", "") or "",
        )
        return self.result

    def call(self, method, params):
        if self.result is None:
            return Called(ok=False, reason=REFUSAL_NOT_INITIALIZED)
        if not self.result.ok:
            return Called(ok=False, reason="session not established: " + self.result.reason)
        try:
            reply = self.transport.request(method, params)
        except EgressRefusalError:
            raise
        except Exception as exc:
            return Called(ok=False, reason=method + " failed: " + err_name(exc))
        if not isinstance(reply, dict):
            return Called(ok=False, reason=method + " returned no object")
        return Called(ok=True, payload=reply)

    def tools_list(self):
        return self.call("tools/list", {})

    def prompts_list(self):
        return self.call("prompts/list", {})

    def resources_list(self):
        return self.call("resources/list", {})

    def close(self):
        if self.transport is not None and hasattr(self.transport, "close"):
            self.transport.close()
        self.transport = None

