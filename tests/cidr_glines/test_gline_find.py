"""Tests for G-line queries against the CIDR tree (hid/cidr_lookups).

The CIDR tree moved ip-mask G-lines out of GlobalGlineList. The
non-exact gline_find() path used by `GLINE <mask>` queries must keep
the original string-matching ("contained-in") semantics: a wildcard
query like *@10.20.* must find the narrower *@10.20.30.0/24 G-line,
exactly as it did when ip G-lines lived on the linear list.

The broken intermediate behavior answered such queries with a
tree walk that returned only G-lines *covering* the queried mask,
so narrower G-lines were no longer found.
"""

import pytest

from irc_client import IRCClient


pytestmark = pytest.mark.single_server

RPL_GLIST = "280"
ERR_NOSUCHGLINE = "512"
RPL_YOUREOPER = "381"


async def oper_up(client):
    await client.send("OPER testoper operpass")
    await client.wait_for(RPL_YOUREOPER)


async def gline_query(client, mask):
    """Send `GLINE <mask>` and return the RPL_GLIST or ERR_NOSUCHGLINE reply."""
    await client.send(f"GLINE {mask}")
    while True:
        msg = await client.recv(timeout=5.0)
        if msg.command in (RPL_GLIST, ERR_NOSUCHGLINE):
            return msg


@pytest.fixture
async def oper(ircd_hub):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.register("cidroper", "testuser", "Test User")
    await oper_up(client)
    yield client
    await client.disconnect()


async def test_wildcard_query_finds_narrower_ip_gline(oper):
    """`GLINE *@10.20.*` must list the narrower *@10.20.30.0/24 G-line."""
    await oper.send("GLINE !+*@10.20.30.0/24 * 3600 :cidr query test")

    # Sanity: the exact query must find the fresh G-line.
    msg = await gline_query(oper, "*@10.20.30.0/24")
    assert msg.command == RPL_GLIST, f"exact query failed: {msg}"

    # The wildcard pattern contains the G-line, so it must be listed.
    msg = await gline_query(oper, "*@10.20.*")
    assert msg.command == RPL_GLIST, (
        "wildcard query must find the narrower ip G-line, got "
        f"{msg.command} {msg.params}"
    )
    assert any("10.20.30.0/24" in p for p in msg.params)

    await oper.send("GLINE !-*@10.20.30.0/24 * 3600 :cleanup")


async def test_broader_cidr_query_does_not_match(oper):
    """`GLINE *@10.30.0.0/16` must NOT report a /24 inside that range.

    The original semantics are pure string matching: a query without
    wildcards only matches a G-line whose mask is the same string.
    """
    await oper.send("GLINE !+*@10.30.40.0/24 * 3600 :cidr query test")

    msg = await gline_query(oper, "*@10.30.40.0/24")
    assert msg.command == RPL_GLIST, f"exact query failed: {msg}"

    msg = await gline_query(oper, "*@10.30.0.0/16")
    assert msg.command == ERR_NOSUCHGLINE, (
        "a broader mask without wildcards must not match a narrower "
        f"G-line, got {msg.command} {msg.params}"
    )

    await oper.send("GLINE !-*@10.30.40.0/24 * 3600 :cleanup")


async def test_non_ip_wildcard_query_finds_ip_gline(oper):
    """A pattern that does not parse as an ipmask must still match by string.

    match("*0.60.70.0/24", "10.60.70.0/24") succeeds even though the
    pattern is not a valid ipmask, and the pre-tree code found such
    G-lines via the linear list scan.
    """
    await oper.send("GLINE !+*@10.60.70.0/24 * 3600 :cidr query test")

    msg = await gline_query(oper, "*@10.60.70.0/24")
    assert msg.command == RPL_GLIST, f"exact query failed: {msg}"

    msg = await gline_query(oper, "*@*0.60.70.0/24")
    assert msg.command == RPL_GLIST, (
        "non-ipmask wildcard pattern must match by string, got "
        f"{msg.command} {msg.params}"
    )

    await oper.send("GLINE !-*@10.60.70.0/24 * 3600 :cleanup")
