# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

# tests/test_file_transfer.py
import asyncio
import contextlib
import json
import os
import hashlib
import uuid
import pytest
import websockets

from socp import server as socp_server
from socp.client import ensure_keys_for_user, load_recipient_pubkey
from socp.crypto import load_private_key_pem, sign_bytes
from socp.utils import b64url_encode_no_padding, b64url_decode_no_padding, json_canonicalize
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

HOST = "127.0.0.1"
PORT = 8765
WS_URL = f"ws://{HOST}:{PORT}"

# helpers 

async def safe_send(ws, msg):
    try:
        await ws.send(json.dumps(msg))
    except websockets.ConnectionClosedOK:
        pass

async def drain_messages(ws, max_msgs=10):
    for _ in range(max_msgs):
        try:
            await asyncio.wait_for(ws.recv(), timeout=0.15)
        except asyncio.TimeoutError:
            break
        except websockets.ConnectionClosedOK:
            break

def make_hello(user_id: str, msg_id: str):
    """Create a signed USER_HELLO frame for a user."""
    ensure_keys_for_user(user_id)
    priv = load_private_key_pem(f"keys/private_{user_id}.pem")
    pub_b64 = open(f"keys/public/{user_id}.pub").read().strip()

    payload = {"pubkey": pub_b64}
    env = {"type": "USER_HELLO", "from": user_id, "id": msg_id, "payload": payload}
    canon = json_canonicalize(env).encode("utf-8")
    env["sig"] = b64url_encode_no_padding(sign_bytes(priv, canon))
    return env

# test 
@pytest.mark.asyncio
async def test_dm_file_transfer_minimal():
    ws_alice = None
    ws_bob = None

    # Start server in test mode 
    srv = asyncio.create_task(socp_server.main(test_mode=True))
    await asyncio.sleep(0.25)  # tiny wait for server to bind

    try:
        # Connect Alice & Bob 
        ws_alice = await websockets.connect(WS_URL)
        ws_bob = await websockets.connect(WS_URL)

        await safe_send(ws_alice, make_hello("alice", "a-hello"))
        await safe_send(ws_bob, make_hello("bob", "b-hello"))

        # Drain initial server messages
        await asyncio.gather(drain_messages(ws_alice), drain_messages(ws_bob))

        # Prepare file transfer
        file_bytes = b"hello 9.4 dm test\n"
        sha256_hex = hashlib.sha256(file_bytes).hexdigest()
        file_id = str(uuid.uuid4())

        alice_pub = load_recipient_pubkey("alice")
        ct = alice_pub.encrypt(
            file_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        ct_b64 = b64url_encode_no_padding(ct)

        ts0 = 1700000700000
        start = {
            "type": "FILE_START",
            "from": "bob",
            "to": "alice",
            "ts": ts0,
            "payload": {
                "file_id": file_id,
                "name": "unit.txt",
                "size": len(file_bytes),
                "sha256": sha256_hex,
                "mode": "dm",
            },
        }
        chunk = {
            "type": "FILE_CHUNK",
            "from": "bob",
            "to": "alice",
            "ts": ts0 + 500,
            "payload": {"file_id": file_id, "index": 0, "ciphertext": ct_b64},
        }
        end = {
            "type": "FILE_END",
            "from": "bob",
            "to": "alice",
            "ts": ts0 + 1000,
            "payload": {"file_id": file_id},
        }

        # Send frames safely 
        await safe_send(ws_bob, start)
        await safe_send(ws_bob, chunk)
        await safe_send(ws_bob, end)

        # Receive frames
        received_start = received_chunk = received_end = None
        deadline = asyncio.get_running_loop().time() + 3.0
        while asyncio.get_running_loop().time() < deadline:
            try:
                raw = await asyncio.wait_for(ws_alice.recv(), timeout=0.5)
            except (asyncio.TimeoutError, websockets.ConnectionClosedOK):
                continue
            msg = json.loads(raw)
            if msg.get("payload", {}).get("file_id") != file_id:
                continue
            if msg["type"] == "FILE_START":
                received_start = msg
            elif msg["type"] == "FILE_CHUNK":
                received_chunk = msg
            elif msg["type"] == "FILE_END":
                received_end = msg
            if received_start and received_chunk and received_end:
                break

        # Assertions
        assert received_start is not None, "Did not receive FILE_START"
        assert received_chunk is not None, "Did not receive FILE_CHUNK"
        assert received_end is not None, "Did not receive FILE_END"

        pl = received_start["payload"]
        assert pl["name"] == "unit.txt"
        assert pl["size"] == len(file_bytes)
        assert pl["sha256"] == sha256_hex
        assert pl["mode"] == "dm"

        # Decrypt the chunk with Alice's private key
        alice_priv = load_private_key_pem(os.path.join("keys", "private_alice.pem"))
        ct_recv = b64url_decode_no_padding(received_chunk["payload"]["ciphertext"])
        pt = alice_priv.decrypt(
            ct_recv,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        assert pt == file_bytes, "Decrypted chunk does not match original content"

    finally:
        # Cleanup
        with contextlib.suppress(Exception):
            await ws_alice.close()
        with contextlib.suppress(Exception):
            await ws_bob.close()
        srv.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await srv
