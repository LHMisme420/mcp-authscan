import json
import urllib.request

from mcp_authscan.decoy_auth_server import start_decoy, stop_decoy


def test_metadata_points_at_decoy_issuer():
    server = start_decoy()
    try:
        url = server.base_url + "/.well-known/oauth-protected-resource"
        body = json.load(urllib.request.urlopen(url))
        # The decoy advertises its OWN base URL as the authorization server, so
        # discovery is reachable and the issuer binding is actually exercised.
        # A placeholder (https://decoy.invalid) is unreachable and would end the
        # flow before the token request.
        assert body["authorization_servers"] == [server.base_url]
        assert body["resource"].endswith("/mcp")

        as_url = server.base_url + "/.well-known/oauth-authorization-server"
        as_body = json.load(urllib.request.urlopen(as_url))
        assert as_body["issuer"] == server.base_url
    finally:
        stop_decoy(server)


def test_token_endpoint_records_credentials():
    server = start_decoy()
    try:
        req = urllib.request.Request(
            server.base_url + "/token",
            data=b"grant_type=client_credentials",
            headers={"Authorization": "Basic ZGVjb3k6c2VjcmV0"},
            method="POST",
        )
        urllib.request.urlopen(req)
        assert len(server.captured) == 1
        assert server.captured[0]["authorization"].startswith("Basic ")
    finally:
        stop_decoy(server)


def test_capture_is_empty_when_client_never_calls():
    server = start_decoy()
    try:
        assert server.captured == []
    finally:
        stop_decoy(server)
