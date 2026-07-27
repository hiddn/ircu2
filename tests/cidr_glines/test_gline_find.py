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
RPL_ENDOFGLIST = "281"
ERR_NOSUCHGLINE = "512"
RPL_YOUREOPER = "381"


async def oper_up(client):
    await client.send("OPER testoper operpass")
    await client.wait_for(RPL_YOUREOPER)


async def gline_query(client, mask):
    """Send `GLINE <mask>` and return every RPL_GLIST reply (as a list).

    gline_list() can report every matching G-line for a query now, not
    just the first, so this drains the full reply stream up to
    RPL_ENDOFGLIST/ERR_NOSUCHGLINE instead of returning after a single
    message -- otherwise leftover buffered replies would corrupt
    whatever is read next on this connection. Returns [] on
    ERR_NOSUCHGLINE.
    """
    await client.send(f"GLINE {mask}")
    matches = []
    while True:
        msg = await client.recv(timeout=5.0)
        if msg.command == ERR_NOSUCHGLINE:
            return []
        if msg.command == RPL_GLIST:
            matches.append(msg)
        elif msg.command == RPL_ENDOFGLIST:
            return matches


@pytest.fixture
async def oper(ircd_hub):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.register("cidroper", "testuser", "Test User")
    await oper_up(client)
    yield client
    await client.disconnect()


def _texts(matches):
    """Flatten every param of every reply into one list, for substring checks."""
    return [p for msg in matches for p in msg.params]


async def test_wildcard_query_finds_narrower_ip_gline(oper):
    """`GLINE *@10.20.*` must list the narrower *@10.20.30.0/24 G-line."""
    await oper.send("GLINE !+*@10.20.30.0/24 * 3600 :cidr query test")

    # Sanity: the exact query must find the fresh G-line.
    matches = await gline_query(oper, "*@10.20.30.0/24")
    assert matches, "exact query failed to find the fresh G-line"

    # The wildcard pattern contains the G-line, so it must be listed
    # among the (possibly several) matches.
    matches = await gline_query(oper, "*@10.20.*")
    assert any("10.20.30.0/24" in t for t in _texts(matches)), (
        "wildcard query must find the narrower ip G-line, got "
        f"{[(m.command, m.params) for m in matches]}"
    )

    await oper.send("GLINE !-*@10.20.30.0/24 * 3600 :cleanup")


async def test_broader_cidr_query_does_not_match(oper):
    """`GLINE *@10.30.0.0/16` must NOT report a /24 inside that range.

    The original semantics are pure string matching: a query without
    wildcards only matches a G-line whose mask is the same string. Other,
    unrelated G-lines (e.g. a family-ambiguous catch-all left behind by
    another test in this session) may legitimately also match the /16
    query -- what must not happen is the narrower /24 mask itself
    showing up.
    """
    await oper.send("GLINE !+*@10.30.40.0/24 * 3600 :cidr query test")

    matches = await gline_query(oper, "*@10.30.40.0/24")
    assert matches, "exact query failed to find the fresh G-line"

    matches = await gline_query(oper, "*@10.30.0.0/16")
    assert not any("10.30.40.0/24" in t for t in _texts(matches)), (
        "a broader mask without wildcards must not match a narrower "
        f"G-line, got {[(m.command, m.params) for m in matches]}"
    )

    await oper.send("GLINE !-*@10.30.40.0/24 * 3600 :cleanup")


async def test_non_ip_wildcard_query_finds_ip_gline(oper):
    """A pattern that does not parse as an ipmask must still match by string.

    match("*0.60.70.0/24", "10.60.70.0/24") succeeds even though the
    pattern is not a valid ipmask, and the pre-tree code found such
    G-lines via the linear list scan.
    """
    await oper.send("GLINE !+*@10.60.70.0/24 * 3600 :cidr query test")

    matches = await gline_query(oper, "*@10.60.70.0/24")
    assert matches, "exact query failed to find the fresh G-line"

    matches = await gline_query(oper, "*@*0.60.70.0/24")
    assert any("10.60.70.0/24" in t for t in _texts(matches)), (
        "non-ipmask wildcard pattern must match by string, got "
        f"{[(m.command, m.params) for m in matches]}"
    )

    await oper.send("GLINE !-*@10.60.70.0/24 * 3600 :cleanup")
