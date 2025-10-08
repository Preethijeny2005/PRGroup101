# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import asyncio
import json
import pytest
import websockets

from socp import server as socp_server
from socp import tables
from socp.utils import json_canonicalize, b64url_encode_no_padding, b64url_decode_no_padding
from socp.crypto import (
    generate_rsa4096,
    export_public_base64url,
    import_public_base64url,
    sign_bytes,
    verify_bytes,
)

HOST = "127.0.0.1"
PORT = 8765
WS_URL = f"ws://{HOST}:{PORT}"


@pytest.mark.asyncio
async def test_server_handshake_and_link(running_server):
    """
    Positive path:
    - Generate a peer server keypair.
    - Add its public key to EXPECTED_SERVER_PUBS allow-list.
    - Send signed SERVER_HELLO_JOIN.
    - Expect signed SERVER_WELCOME; verify signature.
    - Ensure link is recorded in tables.servers.
    """
    # Arrange: create a "peer server" identity and allow-list it
    peer_id = "srvPeer"
    peer_priv, peer_pub = generate_rsa4096()
    peer_pub_b64 = export_public_base64url(peer_pub)

    # Make the listening server trust this peer_id -> pubkey
    socp_server.EXPECTED_SERVER_PUBS[peer_id] = peer_pub

    # Act: connect as the peer and send signed SERVER_HELLO_JOIN
    async with websockets.connect(WS_URL) as ws:
        payload = {"server_id": peer_id, "pubkey": peer_pub_b64, "ts": "now"}
        env = {
            "id": "m-1",
            "type": "SERVER_HELLO_JOIN",
            "from": peer_id,
            "to": socp_server.SERVER_ID,  # optional, but helpful
            "ts": "now",
            "payload": payload,
        }
        canon = json_canonicalize(env).encode("utf-8")
        env["sig"] = b64url_encode_no_padding(sign_bytes(peer_priv, canon))
        await ws.send(json.dumps(env))

        # Expect a signed SERVER_WELCOME
        raw = await asyncio.wait_for(ws.recv(), timeout=1.5)
        welcome = json.loads(raw)
        assert welcome.get("type") == "SERVER_WELCOME"
        assert welcome.get("from") == socp_server.SERVER_ID
        assert "sig" in welcome, "SERVER_WELCOME must be signed"

        # Verify signature using the listening server's configured public key
        server_pub = import_public_base64url(socp_server._SERVER_PUB_B64)
        env_copy = dict(welcome)
        env_copy.pop("sig", None)
        canon_w = json_canonicalize(env_copy).encode("utf-8")
        ok = verify_bytes(server_pub, canon_w, b64url_decode_no_padding(welcome["sig"]))
        assert ok, "Failed to verify SERVER_WELCOME signature"

    # Assert: the server recorded the link
    assert peer_id in tables.servers, "Peer link not recorded in tables.servers"
    # Clean up the recorded link to avoid cross-test leakage
    tables.servers.pop(peer_id, None)


@pytest.mark.asyncio
async def test_server_rejects_unknown_peer(running_server):
    """
    Negative path:
    - Connect as a peer with a key that's NOT in EXPECTED_SERVER_PUBS.
    - Send a correctly-signed HELLO_JOIN.
    - Expect NO welcome within a short timeout (reject).
    """
    stranger_id = "srvStranger"
    stranger_priv, stranger_pub = generate_rsa4096()
    stranger_pub_b64 = export_public_base64url(stranger_pub)

    # Ensure it's NOT allow-listed
    socp_server.EXPECTED_SERVER_PUBS.pop(stranger_id, None)

    async with websockets.connect(WS_URL) as ws:
        env = {
            "id": "m-2",
            "type": "SERVER_HELLO_JOIN",
            "from": stranger_id,
            "to": socp_server.SERVER_ID,
            "ts": "now",
            "payload": {"server_id": stranger_id, "pubkey": stranger_pub_b64, "ts": "now"},
        }
        canon = json_canonicalize(env).encode("utf-8")
        env["sig"] = b64url_encode_no_padding(sign_bytes(stranger_priv, canon))
        await ws.send(json.dumps(env))

        # We should NOT receive SERVER_WELCOME (unknown peer not in allow-list).
        # The server may either close the connection or stay silent.
        try:
            msg = await asyncio.wait_for(ws.recv(), timeout=0.5)
            data = json.loads(msg)
            assert data.get("type") != "SERVER_WELCOME", "Unexpected WELCOME for unknown peer"
        except asyncio.TimeoutError:
            # OK: server stayed silent and didn't welcome us.
            pass
        except (websockets.exceptions.ConnectionClosedOK,
                websockets.exceptions.ConnectionClosedError):
            # OK: server closed on us — also a valid rejection path.
            pass

    # And it should not be in the link table
    assert stranger_id not in tables.servers
