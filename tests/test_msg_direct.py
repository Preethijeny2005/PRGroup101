# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import asyncio
import pytest
import pytest_asyncio
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from socp import server, utils, crypto, tables

# Fixture: Run server in background

@pytest_asyncio.fixture
async def running_server():
    task = asyncio.create_task(server.main())
    await asyncio.sleep(0.2)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

# Test: MSG_DIRECT end-to-end encrypted message

@pytest.mark.asyncio
async def test_msg_direct_encryption(running_server):
    # Generate sender and recipient RSA keys (4096 bits)
    sender_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    sender_pub = sender_priv.public_key()
    recipient_priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    recipient_pub = recipient_priv.public_key()

    # Register recipient in local_users to receive messages
    recipient_id = "bob"
    recipient_queue = asyncio.Queue()
    class DummyWS:
        async def send(self, msg):
            await recipient_queue.put(msg)

    tables.local_users[recipient_id] = DummyWS()

    # RSA-only encrypt the plaintext directly with recipient RSA-OAEP-SHA256
    plaintext = b"Hello secret"
    ciphertext = recipient_pub.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    # Sign the message with sender private key
    ts = utils.now_ts_iso()
    sig_data = ciphertext + b"alice" + recipient_id.encode() + ts.encode()
    signature = crypto.sign_bytes(sender_priv, sig_data)
    # Build MSG_DIRECT frame with sender_pub and epoch ts
    sender_pub_b64 = crypto.export_public_base64url(sender_pub)
    payload = {
        "ciphertext": utils.b64url_encode_no_padding(ciphertext),
        "content_sig": utils.b64url_encode_no_padding(signature),
        "sender_pub": sender_pub_b64,
        "from": "alice",
        "to": recipient_id,
        "ts": ts
    }

    frame = {
        "type": "MSG_DIRECT",
        "from": "alice",
        "to": recipient_id,
        "payload": payload,
        "id": "msg123",
    }

    # Optional top-level signature over canonicalized envelope
    env_canon = utils.json_canonicalize(dict(frame)).encode()
    env_sig = crypto.sign_bytes(sender_priv, env_canon)
    frame["sig"] = utils.b64url_encode_no_padding(env_sig)

    # Send frame through server routing
    await server.route_to_user(frame)

    # Retrieve message from DummyWS queue
    delivered_msg_json = await recipient_queue.get()
    delivered_msg = json.loads(delivered_msg_json)
    payload = delivered_msg["payload"]

    # Recipient decrypt message (RSA-OAEP-SHA256)
    ciphertext_bytes = utils.b64url_decode_no_padding(payload["ciphertext"])
    plaintext_decrypted = recipient_priv.decrypt(
        ciphertext_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

    assert plaintext_decrypted == plaintext

    # Verify signature over ciphertext || from || to || ts
    sig_valid = crypto.verify_bytes(
        sender_pub,
        ciphertext_bytes +
        payload["from"].encode() +
        payload["to"].encode() +
        payload["ts"].encode(),
        utils.b64url_decode_no_padding(payload["content_sig"])
    )

    assert sig_valid
