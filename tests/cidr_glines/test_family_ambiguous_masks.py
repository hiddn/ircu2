"""Family-ambiguous ip masks must keep matching IPv4 clients.

Masks such as *@* (host "*" parses as an ipmask with bits=0) and
*@::/16 are not IPv4-specific, but their prefix covers the
IPv4-mapped ::ffff:0:0 range, so historically (plain ipmask_check
over the linear G-line list) they matched IPv4 clients as well.

Storing them in the IPv6 side of the CIDR tree broke that: IPv4
clients only search the IPv4 side, and the do_gline() family
short-circuit skipped them on the kill sweep too.

The docker test clients connect over IPv4, so a covering ambiguous
G-line must (a) kill them on activation and (b) block reconnects.

Note: all G-line state changes are confirmed via queries, and any
command issued after a G-line kill goes out on a fresh connection.
There is a pre-existing server quirk (reproducible on unmodified
code paths, e.g. realname G-lines) where a client's queued input
line is never processed if the previous command G-line-killed
another client.
"""

import asyncio
import time

import pytest

from irc_client import IRCClient
from p10_server import P10Server


pytestmark = pytest.mark.single_server

RPL_YOUREOPER = "381"


async def oper_up(client):
    await client.send("OPER testoper operpass")
    await client.wait_for(RPL_YOUREOPER)


async def make_oper(ircd_hub, nick):
    client = IRCClient()
    await client.connect(ircd_hub["host"], ircd_hub["port"])
    await client.register(nick, "testuser", "Test User")
    await oper_up(client)
    return client


@pytest.fixture
async def oper(ircd_hub):
    client = await make_oper(ircd_hub, "cidroper")
    yield client
    try:
        await client.disconnect()
    except Exception:
        pass


async def gline_state(oper, mask):
    """Query `GLINE <mask>` and return '+', '-', or None (no such G-line)."""
    await oper.send(f"GLINE {mask}")
    while True:
        msg = await oper.recv(timeout=5.0)
        if msg.command == "512":
            return None
        if msg.command == "280":
            return msg.params[-2]


async def wait_gline_state(oper, mask, want, timeout=10.0):
    """Poll until the G-line reaches the wanted state."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if await gline_state(oper, mask) == want:
            return
        await asyncio.sleep(0.3)
    raise AssertionError(f"G-line {mask} never reached state {want!r}")


async def deactivate_gline(ircd_hub, mask, nick="cidrclean"):
    """Deactivate a G-line from a fresh oper connection and confirm it.

    The deactivation is resent until it takes effect: gline_modify()
    silently ignores a modification whose lastmod equals the G-line's
    current lastmod (same-second version dedup), so a single attempt
    issued in the creation second is dropped.
    """
    cleaner = await make_oper(ircd_hub, nick)
    try:
        deadline = asyncio.get_running_loop().time() + 15.0
        while asyncio.get_running_loop().time() < deadline:
            await cleaner.send(f"GLINE !-{mask} * 3600 :cleanup")
            if await gline_state(cleaner, mask) in ("-", None):
                return
            await asyncio.sleep(1.0)
        raise AssertionError(f"could not deactivate G-line {mask}")
    finally:
        try:
            await cleaner.disconnect()
        except Exception:
            pass


async def victim_is_killed(victim, timeout=5.0):
    """Return True if the victim's connection is closed by the server."""
    try:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return False
            msg = await victim.recv(timeout=remaining)
            if msg.command == "ERROR":
                return True
    except (ConnectionError, asyncio.IncompleteReadError):
        return True


async def test_ipv6_zero_prefix_mask_kills_ipv4_client(ircd_hub, oper):
    """victim@::/16 covers ::ffff:0:0, so it must match IPv4 clients.

    The G-line is scoped by username because do_gline() has no oper
    exemption -- an unscoped mask would kill the issuing oper too.
    """
    victim = IRCClient()
    await victim.connect(ircd_hub["host"], ircd_hub["port"])
    await victim.register("vict5a", "victim", "Test Victim")

    await oper.send("GLINE !+victim@::/16 * 3600 :ambiguous mask test")

    try:
        assert await victim_is_killed(victim), (
            "IPv4 client survived activation of G-line victim@::/16"
        )
    finally:
        await deactivate_gline(ircd_hub, "victim@::/16")
        try:
            await victim.disconnect()
        except Exception:
            pass


async def test_star_host_mask_kills_ipv4_client(ircd_hub):
    """Host "*" parses as an ipmask with bits=0 and must match everyone.

    gline_checkmask() rejects a bare "*" host outright for oper-issued
    G-lines, so this mask can only arrive from a server; inject it
    through a fake U-lined P10 services server.
    """
    victim = IRCClient()
    await victim.connect(ircd_hub["host"], ircd_hub["port"])
    await victim.register("vict5b", "victim", "Test Victim")

    srv = P10Server(name="services.test.net", numeric=4, password="testpass")
    await srv.connect(ircd_hub["host"], ircd_hub["server_port"])
    await srv.handshake()
    now = int(time.time())
    try:
        await srv._send(f"{srv._num} GL * +victim@* 3600 {now} {now + 3600} :star host test")
        assert await victim_is_killed(victim), (
            "IPv4 client survived activation of G-line victim@*"
        )
    finally:
        await srv.disconnect()
        await deactivate_gline(ircd_hub, "victim@*", nick="cidrclnb")
        try:
            await victim.disconnect()
        except Exception:
            pass


async def test_ambiguous_mask_blocks_reconnect(ircd_hub, oper):
    """gline_lookup() must find the ambiguous G-line for IPv4 clients."""
    await oper.send("GLINE !+victim@::/16 * 3600 :ambiguous mask test")
    await wait_gline_state(oper, "victim@::/16", "+")

    victim = IRCClient()
    await victim.connect(ircd_hub["host"], ircd_hub["port"])
    refused = False
    try:
        await victim.send("NICK vict5c")
        await victim.send("USER victim 0 * :Test Victim")
        deadline = asyncio.get_running_loop().time() + 5.0
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            msg = await victim.recv(timeout=remaining)
            if msg.command == "ERROR":
                refused = True
                break
            if msg.command == "001":
                break
    except (ConnectionError, asyncio.IncompleteReadError):
        refused = True
    finally:
        await deactivate_gline(ircd_hub, "victim@::/16", nick="cidrclnc")
        try:
            await victim.disconnect()
        except Exception:
            pass

    assert refused, "IPv4 client registered despite covering victim@::/16 G-line"
