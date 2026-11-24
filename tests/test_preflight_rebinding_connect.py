"""Offline (no real network) tests for the live-scan preflight's destination binding.

Driven through the real entry point, monolith.main(), so the assertion holds no matter how
the internals are refactored: if any live-scan site opens a bare connection, a socket is
created here and the test fails. Name resolution is stubbed at its lowest point
(socket.getaddrinfo); every socket constructor is trapped, so nothing touches the network.

The attacker rebinds: the first resolution answers public (which the destination check
accepts), every later resolution answers loopback. A preflight that binds its check to the
address it actually connects to opens no socket.
"""
import socket
import sys

import pytest

from mcp_authscan import monolith

PUBLIC = "93.184.216.34"
LOOPBACK = "127.0.0.1"
MAPPED_LOOPBACK = "::ffff:127.0.0.1"
PRIVATE = "10.0.0.1"
_AF4, _AF6, _ST = socket.AF_INET, socket.AF_INET6, socket.SOCK_STREAM


def _rec(addr, port=443):
    fam = _AF6 if ":" in addr else _AF4
    sa = (addr, port, 0, 0) if fam == _AF6 else (addr, port)
    return (fam, _ST, 6, "", sa)


def _trap_sockets(monkeypatch):
    opened = []

    def boom(*a, **k):
        opened.append(1)
        raise OSError("test: socket creation blocked (no real network)")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    return opened


def _run_live_scan(monkeypatch, tmp_path, host):
    """Drive a real live scan of https://<host>/mcp through the CLI entry point."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv",
                        ["mcp-authscan", f"https://{host}/mcp", "--contact", "x@example.test",
                         "--authorized-by", "test", "--auth-basis", "test"])
    try:
        monolith.main()
    except SystemExit:
        pass  # the scan always exits; the assertion is about sockets, not the exit code


def test_rebinding_first_public_then_loopback_opens_no_socket(monkeypatch, tmp_path):
    opened = _trap_sockets(monkeypatch)
    calls = {"n": 0}

    def gai(host, port, *a, **k):
        calls["n"] += 1
        return [_rec(PUBLIC, port or 443)] if calls["n"] == 1 else [_rec(LOOPBACK, port or 443)]

    monkeypatch.setattr(socket, "getaddrinfo", gai)
    _run_live_scan(monkeypatch, tmp_path, "rebind.test")
    assert not opened, (
        "the live scan opened %d socket(s): a site connected on a fresh loopback resolution "
        "after the destination check passed on the earlier public answer" % len(opened))


def test_ipv4_mapped_ipv6_loopback_only_opens_no_socket(monkeypatch, tmp_path):
    opened = _trap_sockets(monkeypatch)
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **k: [_rec(MAPPED_LOOPBACK, p or 443)])
    _run_live_scan(monkeypatch, tmp_path, "mapped.test")
    assert not opened, "the live scan opened a socket to an IPv4-mapped IPv6 loopback"


def test_one_public_plus_one_private_opens_no_socket(monkeypatch, tmp_path):
    opened = _trap_sockets(monkeypatch)
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda h, p, *a, **k: [_rec(PUBLIC, p or 443), _rec(PRIVATE, p or 443)])
    _run_live_scan(monkeypatch, tmp_path, "mixed.test")
    assert not opened, "the live scan opened a socket despite a private address in the answer set"
