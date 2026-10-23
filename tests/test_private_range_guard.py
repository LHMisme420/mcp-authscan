"""The private-address guard must cover every non-public range, not a list.

`PRIVATE_IP_RANGES` enumerated ten RFC1918/ULA/loopback networks, and
`validate_target_host()` checked only `addr_info[0][4][0]` - the first record
`getaddrinfo` happened to return. Two consequences:

  * 100.64.0.0/10 (CGNAT, which is also Tailscale's range), 0.0.0.0,
    224.0.0.0/4 (multicast) and 255.255.255.255 were treated as public, so
    `--allow-private`-free scanning reached a Tailscale peer or the local
    "any" address;
  * ::ffff:127.0.0.1 is not "in" 127.0.0.0/8 as an IPv6 object, so an
    IPv4-mapped loopback address passed the check outright.

A name that answered with one public and one private address also passed,
because only the first record was inspected - the scanner validated the public
record and then connected to whatever the resolver order preferred.

`ipaddress.is_global` already knows all of this; the fix is to use it and to
check every record. These tests use IP literals only: no DNS, no connection.
"""
import socket

import pytest

from mcp_authscan import monolith, scan_main

MODULES = [monolith, scan_main]

NON_PUBLIC = [
    ("127.0.0.1", "loopback"),
    ("10.1.2.3", "RFC1918"),
    ("192.168.1.1", "RFC1918"),
    ("172.16.0.1", "RFC1918"),
    ("169.254.169.254", "link-local / cloud metadata"),
    ("100.64.0.1", "CGNAT - also Tailscale's range"),
    ("0.0.0.0", "unspecified / 'any'"),
    ("224.0.0.1", "multicast"),
    ("255.255.255.255", "broadcast"),
    ("::1", "IPv6 loopback"),
    ("fc00::1", "unique local"),
    ("fe80::1", "IPv6 link-local"),
    ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
]

PUBLIC = [("93.184.216.34", "public IPv4 literal"), ("2606:2800:220:1::1", "public IPv6 literal")]


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
@pytest.mark.parametrize("address,why", NON_PUBLIC, ids=[a for a, _ in NON_PUBLIC])
def test_non_public_address_is_private(module, address, why):
    assert module.is_private_ip(address) is True, f"{address} ({why}) treated as public"


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
@pytest.mark.parametrize("address,why", NON_PUBLIC, ids=[a for a, _ in NON_PUBLIC])
def test_validate_target_host_refuses_non_public_literal(module, address, why):
    with pytest.raises(ValueError):
        module.validate_target_host(address, 80)


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
@pytest.mark.parametrize("address,why", PUBLIC, ids=[a for a, _ in PUBLIC])
def test_public_address_is_allowed(module, address, why):
    assert module.is_private_ip(address) is False
    assert module.validate_target_host(address, 443) == address


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
def test_validate_target_host_checks_every_resolved_record(module, monkeypatch):
    """Public record first, private record second: must still be refused."""
    mixed = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 80)),
    ]
    monkeypatch.setattr(module.socket, "getaddrinfo", lambda *a, **k: mixed)
    with pytest.raises(ValueError):
        module.validate_target_host("mixed.example", 80)
