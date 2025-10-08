# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

# tests/helloRemove_test.py
import pytest
import asyncio
import websockets
import json
import uuid

from socp.utils import make_envelope, json_canonicalize, now_ts_iso
from socp.crypto import sign_bytes, export_public_base64url, load_private_key_pem
from base64 import urlsafe_b64encode, urlsafe_b64decode

HOST = "127.0.0.1"
PORT = 8765

# Load test private keys (PEM)
ALICE_PRIV = load_private_key_pem("keys/private_alice.pem")
BOB_PRIV   = load_private_key_pem("keys/private_bob.pem")

def b64u_encode(b: bytes) -> str:
    return urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def sign_frame(frame: dict, priv) -> dict:
    """Sign the frame in-place, returning it"""
    frame_copy = dict(frame)
    frame_copy.pop("sig", None)
    canon = json_canonicalize(frame_copy).encode("utf-8")
    frame["sig"] = b64u_encode(sign_bytes(priv, canon))
    return frame

@pytest.mark.asyncio
async def test_user_hello_ack(running_server):
    user_id = "alice"
    alice_pub_b64 = export_public_base64url(ALICE_PRIV.public_key())

    async with websockets.connect(f"ws://{HOST}:{PORT}") as ws:
        hello = make_envelope("USER_HELLO", user_id, None, {
            "info": "hello",
            "pubkey": alice_pub_b64
        })
        hello = sign_frame(hello, ALICE_PRIV)
        await ws.send(json.dumps(hello))

        ack_msg = await ws.recv()
        ack_frame = json.loads(ack_msg)

        assert ack_frame["type"] == "ACK"
        assert ack_frame["to"] == user_id
        assert ack_frame["payload"]["msg_ref"] == hello["id"]

@pytest.mark.asyncio
async def test_user_remove_on_disconnect(running_server):
    user_id = "bob"
    bob_pub_b64 = export_public_base64url(BOB_PRIV.public_key())

    ws = await websockets.connect(f"ws://{HOST}:{PORT}")
    hello = make_envelope("USER_HELLO", user_id, None, {
        "info": "hi",
        "pubkey": bob_pub_b64
    })
    hello = sign_frame(hello, BOB_PRIV)
    await ws.send(json.dumps(hello))
    await ws.recv()  # ACK

    await ws.close()
    await asyncio.sleep(0.2)

    from socp import tables
    assert user_id not in tables.local_users

@pytest.mark.asyncio
async def test_user_advertise_message(running_server):
    ws1 = await websockets.connect(f"ws://{HOST}:{PORT}")
    ws2 = await websockets.connect(f"ws://{HOST}:{PORT}")

    alice_pub_b64 = export_public_base64url(ALICE_PRIV.public_key())
    bob_pub_b64 = export_public_base64url(BOB_PRIV.public_key())

    alice_hello = make_envelope("USER_HELLO", "alice", None, {"info": "hi", "pubkey": alice_pub_b64})
    bob_hello   = make_envelope("USER_HELLO", "bob", None, {"info": "hi", "pubkey": bob_pub_b64})

    alice_hello = sign_frame(alice_hello, ALICE_PRIV)
    bob_hello   = sign_frame(bob_hello, BOB_PRIV)

    await ws1.send(json.dumps(alice_hello))
    await _recv_until(ws1, "ACK")
    await ws2.send(json.dumps(bob_hello))
    await _recv_until(ws2, "ACK")

    # Alice sends direct chat to Bob
    chat_msg = make_envelope("MSG_DIRECT", "alice", "bob", {"text": "Hello Bob!"})
    chat_msg = sign_frame(chat_msg, ALICE_PRIV)
    await ws1.send(json.dumps(chat_msg))

    # Wait until USER_DELIVER (skip any PUBLIC_CHANNEL frames)
    frame = await _recv_until(ws2, "USER_DELIVER")

    assert frame["type"] == "USER_DELIVER"
    assert frame["from"] == "alice"
    assert frame["to"] == "bob"
    assert frame["payload"]["text"] == "Hello Bob!"

    await ws1.close()
    await ws2.close()

async def _recv_until(ws, target_type: str):
    """
    Receive frames until one matches target_type.
    Returns the first matching frame.
    """
    while True:
        raw = await ws.recv()
        frame = json.loads(raw)
        if frame["type"] == target_type:
            return frame
