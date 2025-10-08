# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import asyncio
import websockets
import json
import uuid
import os
import time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from .db import init_db, add_user, join_group
from socp.db import add_user, join_group, init_db
import argparse

# Explicit imports for clarity
from .tables import (
    local_users,
    servers,
    user_locations,
    user_sessions,
    route_to_user,
    set_user_session,
    remove_user_session,
    remove_server,
)
from . import tables

from .utils import make_envelope, json_canonicalize, now_ts_iso
from . import config

from socp.crypto import (
    generate_rsa4096,
    import_public_base64url,
    export_public_base64url as export_pub_b64url,
    sign_bytes,
    verify_bytes,
    export_public_base64url,
    verify_bytes,
    load_private_key_pem,
    save_private_key_pem,
)
from socp.utils import b64url_encode_no_padding, b64url_decode_no_padding

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Config loading (top of server.py) 
import os, yaml

CONFIG_PATH = os.path.abspath(os.getenv("CONFIG", "config.yaml"))
try:
    with open(CONFIG_PATH, "r") as f:
        CONF = yaml.safe_load(f) or {}
except FileNotFoundError:
    print(f"[boot] could not open {CONFIG_PATH} (FileNotFoundError); using empty config")
    CONF = {}

HOST = os.getenv("HOST", (CONF.get("server", {}) or {}).get("host", "127.0.0.1"))
PORT = int(os.getenv("PORT", (CONF.get("server", {}) or {}).get("port", 8765)))
SERVER_ID = os.getenv("SERVER_ID", (CONF.get("server", {}) or {}).get("id") or f"{HOST}:{PORT}")

# Accept both keys; normalize to include an id
_bootstrap = CONF.get("bootstrap") or CONF.get("bootstrap_servers") or []
print(f"[boot] CONFIG={CONFIG_PATH} peers_raw_keys={list(CONF.keys())} peers_listlen={len(_bootstrap)}")
for e in _bootstrap:
    print("[boot] raw peer entry:", e)

BOOTSTRAP = []
for entry in _bootstrap:
    peer_host = entry["host"]; peer_port = entry["port"]
    peer_id = entry.get("id") or f"{peer_host}:{peer_port}"
    BOOTSTRAP.append({"id": peer_id, "host": peer_host, "port": peer_port, "pubkey": entry["pubkey"]})

EXPECTED_SERVER_PUBS = {}
for e in BOOTSTRAP:
    try:
        EXPECTED_SERVER_PUBS[e["id"]] = import_public_base64url(e["pubkey"])
    except Exception:
        pass

# Build expected pubkey map for signature checks
EXPECTED_SERVER_PUBS = {}
for e in BOOTSTRAP:
    try:
        EXPECTED_SERVER_PUBS[e["id"]] = import_public_base64url(e["pubkey"])
    except Exception:
        pass



# (Optional but handy while debugging)
print(f"[boot] CONFIG={CONFIG_PATH} SERVER_ID={SERVER_ID} HOST={HOST} PORT={PORT} peers={len(BOOTSTRAP)}")
for e in BOOTSTRAP:
    print(f"[boot] peer {e['id']} -> ws://{e['host']}:{e['port']}")


# Channel key (RSA-4096) generated once and stored in tables 
def _ensure_public_channel_key():
    if tables.channel_priv_bytes is None or tables.channel_pub_b64 is None:
        priv, pub = generate_rsa4096()
        tables.channel_pub_b64 = export_pub_b64url(pub)
        tables.channel_priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
_ensure_public_channel_key()

def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent

def _load_user_public_key(user_id: str):
    """Load a user's RSA public key from keys/public/<user>.pub (PEM or base64url DER)."""
    pub_dir = _project_root() / "keys" / "public"
    path = pub_dir / f"{user_id}.pub"
    if not path.exists():
        raise FileNotFoundError(f"Missing user pubkey at {path}")
    data = path.read_bytes()
    # Try PEM
    try:
        return serialization.load_pem_public_key(data, backend=default_backend())
    except Exception:
        pass
    # Try base64url DER
    try:
        b64u = data.decode("utf-8").strip()
        return import_public_base64url(b64u)
    except Exception as e:
        raise ValueError(f"Unsupported public key format for {user_id}: {e}")

# Hybrid wrap of channel PRIVATE key (so members can decrypt /all) 
def _wrap_channel_priv_for_member(user_id: str) -> str:
    """
    AES-GCM encrypt the channel private key (tables.channel_priv_bytes),
    wrap the AES key with member's RSA-OAEP(SHA-256), pack as JSON, base64url encode.
    """
    if not tables.channel_priv_bytes:
        raise RuntimeError("channel_priv_bytes not initialized")

    user_pub = _load_user_public_key(user_id)

    # 32-byte AES key, 12-byte nonce
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aead = AESGCM(aes_key)
    ct = aead.encrypt(nonce, tables.channel_priv_bytes, None)  # ct = ciphertext||tag

    # OAEP-wrap AES key
    ek = user_pub.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    package = {
        "alg": "A256GCM+RSAOAEP",
        "iv": b64url_encode_no_padding(nonce),
        "ek": b64url_encode_no_padding(ek),
        "ct": b64url_encode_no_padding(ct),
    }
    # Return base64url(JSON)
    return b64url_encode_no_padding(json.dumps(package, separators=(",", ":")).encode("utf-8"))

# Broadcast helpers 
def _stamp(env: dict):
    env.setdefault("id", str(uuid.uuid4()))
    env.setdefault("from", SERVER_ID)          # concrete server id, not the string "server"
    env.setdefault("ts", int(time.time() * 1000))
    return env

async def _broadcast_to_servers(frame: dict):
    data = json.dumps(frame)
    for sid, server_ws in list(servers.items()):
        try:
            await server_ws.send(data)
        except Exception as e:
            print(f"Error sending to server {sid}: {e}")

async def _send_to_local_user(user_id: str, frame: dict):
    if user_id in local_users:
        try:
            await local_users[user_id].send(json.dumps(frame))
        except Exception as e:
            print(f"Error sending to local user {user_id}: {e}")

async def _broadcast_public_add_updated(new_members: list[str]):
    """
    Emit PUBLIC_CHANNEL_ADD then PUBLIC_CHANNEL_UPDATED snapshot.
    UPDATED includes per-member wrapped key so clients can decrypt.
    Top-level sig is signed with channel private key.
    """
    # ADD
    add_payload = {"add": new_members, "if_version": tables.public_version - 1}
    add_frame = {
        "type": "PUBLIC_CHANNEL_ADD",
        "from": "server",
        "to": "*",
        "ts": 0,
        "payload": add_payload,
    }
    _stamp(add_frame)

    # Sign ADD with channel private key
    ch_priv = load_der_private_key(tables.channel_priv_bytes, password=None)
    canon_add = json_canonicalize({k:v for k,v in add_frame.items() if k!="sig"}).encode("utf-8")
    add_frame["sig"] = b64url_encode_no_padding(sign_bytes(ch_priv, canon_add))

    await _broadcast_to_servers(add_frame)
    # Also inform all local users (not mandatory in the spec, but convenient)
    for uid in local_users.keys():
        await _send_to_local_user(uid, add_frame)

    # UPDATED snapshot with wraps
    wraps = []
    for m in sorted(tables.public_members):
        if m not in tables.public_wraps or tables.public_wraps[m] == "noop":
            try:
                tables.public_wraps[m] = _wrap_channel_priv_for_member(m)
            except Exception as e:
                print(f"Wrap error for {m}: {e}")
                tables.public_wraps[m] = "noop"
        wraps.append({"member_id": m, "wrapped_key": tables.public_wraps[m]})

    upd_payload = {
        "version": tables.public_version,
        "wraps": wraps,
    }
    upd_frame = {
        "type": "PUBLIC_CHANNEL_UPDATED",
        "from": "server",
        "to": "*",
        "ts": 0,
        "payload": upd_payload,
    }
    _stamp(upd_frame)

    canon_upd = json_canonicalize({k:v for k,v in upd_frame.items() if k!="sig"}).encode("utf-8")
    upd_frame["sig"] = b64url_encode_no_padding(sign_bytes(ch_priv, canon_upd))

    await _broadcast_to_servers(upd_frame)
    for uid in local_users.keys():
        await _send_to_local_user(uid, upd_frame)

async def _public_channel_bootstrap_for_user(user_id: str):
    """
    Resend the wrapped channel private key (for this member only) and the current UPDATED snapshot.
    """
    # Ensure we have a wrapped share for this member
    try:
        if user_id not in tables.public_wraps or tables.public_wraps[user_id] == "noop":
            tables.public_wraps[user_id] = _wrap_channel_priv_for_member(user_id)
    except Exception as e:
        print(f"Wrap error for {user_id}: {e}")
        tables.public_wraps[user_id] = "noop"

    # KEY_SHARE (to this user only)
    ch_priv = load_der_private_key(tables.channel_priv_bytes, password=None)
    share_payload = {
        "shares": [{"member": user_id, "wrapped_public_channel_key": tables.public_wraps[user_id]}],
        "creator_pub": tables.channel_pub_b64,
    }
    share_payload["content_sig"] = b64url_encode_no_padding(
        sign_bytes(ch_priv, json_canonicalize(share_payload).encode("utf-8"))
    )
    share_frame = {
        "type": "PUBLIC_CHANNEL_KEY_SHARE",
        "from": "server",
        "to": user_id,
        "ts": int(time.time() * 1000),
        "payload": share_payload,
    }
    canon_share = json_canonicalize({k: v for k, v in share_frame.items() if k != "sig"}).encode("utf-8")
    share_frame["sig"] = b64url_encode_no_padding(sign_bytes(ch_priv, canon_share))
    await _send_to_local_user(user_id, share_frame)

    # UPDATED snapshot (to this user only)
    wraps = []
    for m in sorted(tables.public_members):
        if m not in tables.public_wraps or tables.public_wraps[m] == "noop":
            try:
                tables.public_wraps[m] = _wrap_channel_priv_for_member(m)
            except Exception as e:
                print(f"Wrap error for {m}: {e}")
                tables.public_wraps[m] = "noop"
        wraps.append({"member_id": m, "wrapped_key": tables.public_wraps[m]})

    upd_payload = {"version": tables.public_version, "wraps": wraps}
    upd_frame = {
        "type": "PUBLIC_CHANNEL_UPDATED",
        "from": "server",
        "to": user_id,
        "ts": int(time.time() * 1000),
        "payload": upd_payload,
    }
    canon_upd = json_canonicalize({k: v for k, v in upd_frame.items() if k != "sig"}).encode("utf-8")
    upd_frame["sig"] = b64url_encode_no_padding(sign_bytes(ch_priv, canon_upd))
    await _send_to_local_user(user_id, upd_frame)



async def _public_channel_on_user_join(new_user: str):
    # treat every connection as a join for key delivery
    is_new = new_user not in tables.public_members
    if is_new:
        tables.public_members.add(new_user)
        tables.public_version += 1

    # Always build a wrapped key for THIS user
    try:
        wrapped = _wrap_channel_priv_for_member(new_user)
    except Exception as e:
        print(f"Wrap error for {new_user}: {e}")
        wrapped = "noop"

    payload = {
        "shares": [
            {"member": new_user, "wrapped_public_channel_key": wrapped}
        ],
        "creator_pub": tables.channel_pub_b64,
    }
    ch_priv = load_der_private_key(tables.channel_priv_bytes, password=None)
    content_to_sign = json_canonicalize(payload).encode("utf-8")
    payload["content_sig"] = b64url_encode_no_padding(sign_bytes(ch_priv, content_to_sign))

    share_frame = {
        "type": "PUBLIC_CHANNEL_KEY_SHARE",
        "from": "server",
        "to": "*",
        "ts": int(time.time() * 1000),
        "payload": payload,
    }
    canon_share = json_canonicalize({k:v for k,v in share_frame.items() if k!="sig"}).encode("utf-8")
    share_frame["sig"] = b64url_encode_no_padding(sign_bytes(ch_priv, canon_share))

    # Route only to this user (don’t rely on broadcast)
    await _send_to_local_user(new_user, share_frame)

    # Only when they’re new, broadcast ADD/UPDATED to everyone
    if is_new:
        await _broadcast_public_add_updated([new_user])


# Presence gossip 

async def broadcast_user_advertise(user_id: str):
    env = make_envelope(
        "USER_ADVERTISE",
        from_id=SERVER_ID,
        to_id=None,
        payload={"user_id": user_id, "ts": now_ts_iso()},
    )
    # send to all connected peers
    for sid, ws in list(servers.items()):
        try:
            await ws.send(json.dumps(env))
        except Exception as e:
            print(f"[presence] advertise to {sid} failed: {e}")


async def cleanup_user(user_id: str):
    changed = False
    if user_id in local_users:
        del local_users[user_id]; changed = True
    if user_id in user_locations:
        del user_locations[user_id]; changed = True
    if user_id in user_sessions:
        remove_user_session(user_id); changed = True

    if changed:
        remove_msg = make_envelope("USER_REMOVE", from_id="server", to_id=None,
                                   payload={"user_id": user_id, "ts": now_ts_iso()})
        for server_ws in servers.values():
            try: await server_ws.send(json.dumps(remove_msg))
            except Exception as e: print(f"Error sending USER_REMOVE to server: {e}")
        print(f"Cleaned up user {user_id}")


# Frame handler 
async def handle_frame(frame):
    user_id = frame.get("from")
    target  = frame.get("to")
    ftype   = frame.get("type")
    payload = frame.get("payload") or {}

    # Simple WHO 
    if ftype == "WHO":
        users_list = list(local_users.keys())
        reply = {
            "type": "WHO",
            "from": SERVER_ID,          # concrete server id
            "to": user_id,
            "payload": {"users": users_list},
        }
        if user_id in local_users:
            await local_users[user_id].send(json.dumps(reply))
            print(f"Sent WHO response to {user_id}")
        else:
            print(f"WHO request from unknown user {user_id}")
        return

    # Inter-server gossip (do NOT route)
    if ftype == "SERVER_ANNOUNCE":
        info = frame.get("payload") or {}
        print(f"[link] announce: {info.get('server_id')} (from {frame.get('from')})")
        return

    if ftype == "USER_ADVERTISE":
        # learn where a remote user lives
        uid  = (payload or {}).get("user_id")
        host = frame.get("from")
        if uid and host:
            # Do not overwrite locals; only learn remote locations for users we don't host.
            if uid not in local_users:
                user_locations[uid] = host
                print(f"[presence] learned {uid} @ {host}")
            else:
                # Keep our authoritative local mapping
                print(f"[presence] ignore remote advertise for local user {uid} from {host}")
        return


    # Public channel control frames (consume + fan-in locally) 
    if ftype == "PUBLIC_CHANNEL_KEY_SHARE":
        payload = frame.get("payload", {}) or {}
        shares  = payload.get("shares") or []
        delivered = 0
        for s in shares:
            member = s.get("member")
            if member in local_users:
                try:
                    await _send_to_local_user(member, frame)
                    delivered += 1
                except Exception as e:
                    print(f"Error delivering KEY_SHARE to {member}: {e}")
        if delivered:
            print(f"[public] delivered KEY_SHARE to {delivered} local member(s)")
        # Re-relay to other servers (best-effort)
        return
    
    if ftype == "PUBLIC_CHANNEL_ADD":
        # Optional: update local copy if you want strict cross-server consensus
        # but at least don't try to route a '*' address.
        # Fan-out to local users so their clients can update UI.
        for uid in local_users.keys():
            await _send_to_local_user(uid, frame)
        return

    if ftype == "PUBLIC_CHANNEL_UPDATED":
        # Optional: persist wraps/version; minimally, just show to locals.
        for uid in local_users.keys():
            await _send_to_local_user(uid, frame)
        return

    # Public channel messages (fan-out; never decrypt)
    if ftype == "MSG_PUBLIC_CHANNEL":
        base_id = frame.get("id") or str(uuid.uuid4())
        from_id = frame.get("from", "unknown")
        for member in sorted(tables.public_members):
            deliver = {
                "type": "USER_DELIVER" if member in local_users else "SERVER_DELIVER",
                "from": from_id,
                "to": member,
                "payload": frame.get("payload", {}),
                "id": f"{base_id}:{member}",
                "ts": frame.get("ts"),
            }
            if member in local_users:
                try:
                    await local_users[member].send(json.dumps(deliver))
                    print(f"Delivered public msg {deliver['id']} to local user {member}")
                except Exception as e:
                    print(f"Error delivering public msg to {member}: {e}")
            elif member in user_locations:
                try:
                    await route_to_user(deliver)  # forward to remote server
                    print(f"Forwarded public msg {deliver['id']} to remote user {member}")
                except Exception as e:
                    print(f"Error routing public msg to {member}: {e}")
            else:
                # unknown user; skip
                pass
        return

    # Direct messages
    if ftype == "MSG_DIRECT":
        target = frame.get("to")
        if target in local_users:
            deliver = {
                "type": "USER_DELIVER",
                "from": frame.get("from"),
                "to": target,
                "payload": frame.get("payload", {}),
                "id": frame.get("id"),
                "ts": frame.get("ts"),
            }
            await local_users[target].send(json.dumps(deliver))
            print(f"Delivered MSG_DIRECT {frame.get('id')} to local user {target}")
            return

        deliver = {
            "type": "SERVER_DELIVER",
            "from": frame.get("from"),
            "to": target,  # keep this as the USER id
            "payload": frame.get("payload", {}),
            "id": frame.get("id"),
            "ts": frame.get("ts"),
        }

        if target in user_locations:
            await route_to_user(deliver)
            print(f"Forwarded MSG_DIRECT {frame.get('id')} to user {target} via server")
        else:
            await _broadcast_to_servers(deliver)
            print(f"[route] no mapping for {target}; fanned out {frame.get('id')} to peers")
        return



    # Receiving side of forwarded delivery
    if ftype == "SERVER_DELIVER":
        target_user = frame.get("to")
        if not target_user:
            print("SERVER_DELIVER missing 'to'; dropping")
            return

        if target_user in local_users:
            deliver = {
                "type": "USER_DELIVER",
                "from": frame.get("from"),
                "to": target_user,
                "payload": frame.get("payload", {}),
                "id": frame.get("id"),
                "ts": frame.get("ts"),
            }
            try:
                await local_users[target_user].send(json.dumps(deliver))
                print(f"Delivered SERVER_DELIVER {frame.get('id')} to local user {target_user}")
            except Exception as e:
                print(f"Error delivering SERVER_DELIVER to {target_user}: {e}")
            return

        # Not local anymore? try to route again (presence may have moved)
        await route_to_user(frame)
        return

        # File transfer (DM or Public)
    if ftype in ("FILE_START", "FILE_CHUNK", "FILE_END"):
        base_id = frame.get("id") or str(uuid.uuid4())

        async def _deliver(member: str):
            out = dict(frame)
            out["to"] = member
            out["id"] = f"{base_id}:{member}"
            if member in local_users:
                await _send_to_local_user(member, out)
                print(f"Delivered {out['type']} {out.get('payload',{}).get('file_id','?')} to local user {member}")
            elif member in user_locations:
                try:
                    await route_to_user(out)
                    print(f"Forwarded {out['type']} {out.get('payload',{}).get('file_id','?')} to remote user {member}")
                except Exception as e:
                    print(f"Error routing file frame to {member}: {e}")
            else:
                print(f"Unknown recipient {member}, dropping {out['type']} {out.get('payload',{}).get('file_id','?')}")

        if target == "public":
            for member in sorted(tables.public_members):
                await _deliver(member)
        else:
            await _deliver(target)
        return


    # Fallback
    await route_to_user(frame)



# Server keypair (authN / message signing)
_SERVER_PRIV = None
_SERVER_PUB_B64 = None

def _ensure_server_keys():
    global _SERVER_PRIV, _SERVER_PUB_B64
    # respect KEYS_DIR so each server can have its own key
    keys_dir = os.getenv("KEYS_DIR", os.path.join(os.path.dirname(__file__), "..", "keys"))
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "server_private.pem")

    if os.path.exists(priv_path):
        _SERVER_PRIV = load_private_key_pem(priv_path)
    else:
        _SERVER_PRIV, _ = generate_rsa4096()
        save_private_key_pem(_SERVER_PRIV, priv_path)

    _SERVER_PUB_B64 = export_public_base64url(_SERVER_PRIV.public_key())
    print(f"[boot] using key at {priv_path}")
    print(f"[boot] my pubkey(head): {_SERVER_PUB_B64[:36]}…")

_ensure_server_keys()


async def _announce(server_ws, new_id: str):
    """Send SERVER_ANNOUNCE (signed) to a specific peer."""
    payload = {"server_id": new_id, "ts": now_ts_iso()}
    env = {
        "id": str(uuid.uuid4()),
        "type": "SERVER_ANNOUNCE",
        "from": SERVER_ID,
        "ts": now_ts_iso(),
        "payload": payload,
    }
    canon = json_canonicalize(env).encode("utf-8")
    env["sig"] = b64url_encode_no_padding(sign_bytes(_SERVER_PRIV, canon))
    await server_ws.send(json.dumps(env))

async def _welcome(websocket, peer_id: str):
    """Send SERVER_WELCOME to the newly joined server."""
    payload = {"server_id": SERVER_ID, "pubkey": _SERVER_PUB_B64, "ts": now_ts_iso()}
    env = {
        "id": str(uuid.uuid4()),
        "type": "SERVER_WELCOME",
        "from": SERVER_ID,
        "to": peer_id,
        "ts": now_ts_iso(),
        "payload": payload,
    }
    canon = json_canonicalize(env).encode("utf-8")
    env["sig"] = b64url_encode_no_padding(sign_bytes(_SERVER_PRIV, canon))
    await websocket.send(json.dumps(env))

async def _connect_to_peer(entry):
    """Persistent connector: keep a WS up to the peer; handshake and verify."""
    peer_id = entry["id"]
    uri = f"ws://{entry['host']}:{entry['port']}"
    expected_pub = EXPECTED_SERVER_PUBS.get(peer_id)
    backoff = 1.0
    while True:
        try:
            ws = await websockets.connect(uri)
            # HELLO_JOIN with signature
            payload = {"server_id": SERVER_ID, "pubkey": _SERVER_PUB_B64, "ts": now_ts_iso()}
            env = {
                "id": str(uuid.uuid4()),
                "type": "SERVER_HELLO_JOIN",
                "from": SERVER_ID,
                "to": peer_id,
                "ts": now_ts_iso(),
                "payload": payload,
            }
            canon = json_canonicalize(env).encode("utf-8")
            env["sig"] = b64url_encode_no_padding(sign_bytes(_SERVER_PRIV, canon))
            await ws.send(json.dumps(env))

            # Expect WELCOME; verify signature against expected pub
            raw = await ws.recv()
            msg = json.loads(raw)
            if msg.get("type") != "SERVER_WELCOME":
                raise RuntimeError(f"Unexpected first response: {msg.get('type')}")
            sig_b64 = msg.get("sig")
            if not sig_b64:
                raise RuntimeError("WELCOME missing signature")
            if expected_pub is None:
                raise RuntimeError("No expected pubkey configured for peer")
            env_copy = dict(msg); env_copy.pop("sig", None)
            canon = json_canonicalize(env_copy).encode("utf-8")
            if not verify_bytes(expected_pub, canon, b64url_decode_no_padding(sig_b64)):
                raise RuntimeError("WELCOME signature verification failed")

            # Link accepted
            servers[peer_id] = ws
            # advertise all current locals to this just-connected peer
            for uid in list(local_users.keys()):
                try:
                    adv = make_envelope(
                        "USER_ADVERTISE",
                        from_id=SERVER_ID,
                        to_id=None,
                        payload={"user_id": uid, "ts": now_ts_iso()},
                    )
                    await ws.send(json.dumps(adv))
                except Exception as e:
                    print(f"[presence] failed to advertise {uid} to {peer_id}: {e}")

            print(f"[link] connected to {peer_id} @ {uri}")

            # Advertise all currently local users to this new peer
            for uid in list(local_users.keys()):
                try:
                    adv = make_envelope(
                        "USER_ADVERTISE",
                        from_id=SERVER_ID,
                        to_id=None,
                        payload={"user_id": uid, "ts": now_ts_iso()},
                    )
                    await ws.send(json.dumps(adv))
                except Exception as e:
                    print(f"[presence] failed to advertise {uid} to {peer_id}: {e}")

            # Announce this peer to the others, and ourselves to it
            for sid, other in list(servers.items()):
                if other is ws:
                    continue
                try:
                    await _announce(other, peer_id)
                except Exception:
                    pass
            try:
                await _announce(ws, SERVER_ID)
            except Exception:
                pass

            # Keep the socket alive until it breaks
            backoff = 1.0
            async for raw in ws:
                try:
                    frame = json.loads(raw)
                    print(f"[link] recv from {peer_id}: {frame}")
                    await handle_frame(frame)
                except Exception as e:
                    print(f"[link] error reading from {peer_id}: {e}")
        except Exception as e:
            print(f"[link] {peer_id} connect error: {e}")
        finally:
            try:
                if servers.get(peer_id) is ws:
                    del servers[peer_id]
            except Exception:
                pass
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2.0, 30.0)



# WebSocket server 
async def handler(websocket):
    user_id = None
    server_id = None
    try:
        # Expect first message: USER_HELLO or SERVER_HELLO_JOIN
        hello_raw = await websocket.recv()
        msg = json.loads(hello_raw)
        if msg.get("type") == "USER_HELLO":
            # --- 0) Basic fields ---
            user_id = msg.get("from")
            if not user_id:
                err = make_envelope("ERROR", from_id="server", to_id=None,
                                    payload={"reason": "MISSING_FROM"})
                await websocket.send(json.dumps(err))
                await websocket.close()
                return

            # Optional: enforce routing if 'to' is present
            # if msg.get("to") and msg["to"] != SERVER_ID:
            # if SERVER_ID and msg.get("to") and msg["to"] != SERVER_ID:
            #     err = make_envelope("ERROR", from_id="server", to_id=user_id,
            #                         payload={"reason": "WRONG_SERVER"})
            #     await websocket.send(json.dumps(err))
            #     await websocket.close()
            #     return

            payload = msg.get("payload", {}) or {}
            pub_b64 = payload.get("pubkey")
            enc_pub_b64 = payload.get("enc_pubkey") or pub_b64
            sig_b64 = msg.get("sig")

            # Verify the hello with the provided pubkey
            try:
                if not pub_b64 or not sig_b64:
                    raise RuntimeError("Missing pubkey or sig")
                user_pub = import_public_base64url(pub_b64)

                env_copy = dict(msg)
                env_copy.pop("sig", None)  # signature is over the envelope w/o 'sig'
                canon = json_canonicalize(env_copy).encode("utf-8")

                if not verify_bytes(user_pub, canon, b64url_decode_no_padding(sig_b64)):
                    raise RuntimeError("Signature verify failed")
            except Exception as e:
                err = make_envelope("ERROR", from_id="server", to_id=user_id,
                                    payload={"reason": f"HELLO_VERIFY_FAILED: {e}"})
                await websocket.send(json.dumps(err))
                await websocket.close()
                return

            # Reject duplicate local names (NAME_IN_USE) 
            if user_id in local_users:
                err = make_envelope("ERROR", from_id="server", to_id=user_id,
                                    payload={"reason": "NAME_IN_USE"})
                await websocket.send(json.dumps(err))
                await websocket.close()
                return

            # Persist or validate keys on disk (or in your DB later) 
            try:
                pub_dir = _project_root() / "keys" / "public"
                pub_dir.mkdir(parents=True, exist_ok=True)
                pub_path = pub_dir / f"{user_id}.pub"

                if pub_path.exists():
                    stored = pub_path.read_text().strip()
                    if stored != pub_b64:
                        # Policy: reject or implement rotation; we reject for now.
                        err = make_envelope("ERROR", from_id="server", to_id=user_id,
                                            payload={"reason": "KEY_MISMATCH"})
                        await websocket.send(json.dumps(err))
                        await websocket.close()
                        return
                else:
                    pub_path.write_text(pub_b64 + "\n")

                # Optionally store enc_pubkey separately
                enc_dir = _project_root() / "keys" / "public_enc"
                enc_dir.mkdir(parents=True, exist_ok=True)
                (enc_dir / f"{user_id}.pub").write_text((enc_pub_b64 or "") + "\n")
            except Exception as e:
                err = make_envelope("ERROR", from_id="server", to_id=user_id,
                                    payload={"reason": f"PERSIST_KEYS_FAILED: {e}"})
                await websocket.send(json.dumps(err))
                await websocket.close()
                return

            # Normal session setup (your original logic) 
            session_token = str(uuid.uuid4())
            local_users[user_id] = websocket
            user_locations[user_id] = "local"
            set_user_session(user_id, session_token)
            print(f"User {user_id} connected (session: {session_token})")

            key_dir = os.getenv("KEYS_DIR", os.path.join(os.path.dirname(__file__), "..", "keys"))
            key_path = os.path.join(key_dir, f"private_{user_id}.pem")

            with open(key_path, "rb") as f:
                pem_data = f.read()

            privkey_str = pem_data.decode("utf-8")  # store as string in DB

            pake_password = "fake_password"

            display_name = msg.get("from")

            wrapped_key = _wrap_channel_priv_for_member(display_name)

            # Add to database
            await add_user(enc_pub_b64, privkey_str, pake_password, display_name)

            await join_group(user_id, display_name, group_id="public", role="member", wrapped_key=wrapped_key)

            ack = make_envelope(
                "ACK",
                from_id="server",
                to_id=user_id,
                payload={"msg_ref": msg.get("id"), "session_token": session_token},
            )
            await websocket.send(json.dumps(ack))
            await broadcast_user_advertise(user_id)

            # Public-channel bootstrap (first join vs. reconnect) 
            if user_id in tables.public_members:
                # Reconnect: resend this user's wrapped channel key + current snapshot to *this user only*
                await _public_channel_bootstrap_for_user(user_id)
            else:
                await _public_channel_on_user_join(user_id)


        elif msg.get("type") == "SERVER_HELLO_JOIN":
            # Verify the HELLO signature against expected pubkey from config
            server_id = msg.get("from")
            payload = msg.get("payload", {})
            sig_b64 = msg.get("sig")
            if not server_id or not sig_b64:
                return
            expected_pub = EXPECTED_SERVER_PUBS.get(server_id)
            if expected_pub is None:
                print(f"[link] reject {server_id}: not in bootstrap/known list")
                return
            env_copy = dict(msg)
            env_copy.pop("sig", None)
            canon = json_canonicalize(env_copy).encode("utf-8")
            if not verify_bytes(expected_pub, canon, b64url_decode_no_padding(sig_b64)):
                print(f"[link] reject {server_id}: HELLO signature invalid")
                return
            # Accept and store link
            servers[server_id] = websocket
            print(f"[link] accepted {server_id}")
            # Send signed WELCOME (our id + pubkey)
            await _welcome(websocket, server_id)

            for uid in list(local_users.keys()):
                try:
                    adv = make_envelope(
                        "USER_ADVERTISE",
                        from_id=SERVER_ID,
                        to_id=None,
                        payload={"user_id": uid, "ts": now_ts_iso()},
                    )
                    await websocket.send(json.dumps(adv))
                except Exception as e:
                    print(f"[presence] failed to advertise {uid} to {server_id}: {e}")

            # Announce newcomer to already-connected peers
            for sid, other in list(servers.items()):
                if sid == server_id or other is websocket:
                    continue
                try:
                    await _announce(other, server_id)
                except Exception:
                    pass
        
        elif msg.get("type") == "SERVER_WELCOME":
            # Passive accept if a peer dials us and we dial them simultaneously.
            # Verify signature against expected pub, then keep the socket and advertise locals.
            server_id = msg.get("from")
            sig_b64 = msg.get("sig")
            expected_pub = EXPECTED_SERVER_PUBS.get(server_id)
            if server_id and sig_b64 and expected_pub:
                env_copy = dict(msg); env_copy.pop("sig", None)
                canon = json_canonicalize(env_copy).encode("utf-8")
                if verify_bytes(expected_pub, canon, b64url_decode_no_padding(sig_b64)):
                    servers[server_id] = websocket
                    print(f"[link] passively accepted {server_id}")

                    # Advertise our current local users to this peer too
                    for uid in list(local_users.keys()):
                        try:
                            adv = make_envelope(
                                "USER_ADVERTISE",
                                from_id=SERVER_ID,
                                to_id=None,
                                payload={"user_id": uid, "ts": now_ts_iso()},
                            )
                            await websocket.send(json.dumps(adv))
                        except Exception as e:
                            print(f"[presence] failed to advertise {uid} to {server_id}: {e}")
        
        
        elif msg.get("type") == "SERVER_ANNOUNCE":
            # Signed gossip about a server; verify sig and update knowledge.
            announcer = msg.get("from")
            sig_b64 = msg.get("sig")
            expected_pub = EXPECTED_SERVER_PUBS.get(announcer)
            if announcer and sig_b64 and expected_pub:
                env_copy = dict(msg); env_copy.pop("sig", None)
                canon = json_canonicalize(env_copy).encode("utf-8")
                if verify_bytes(expected_pub, canon, b64url_decode_no_padding(sig_b64)):
                    info = msg.get("payload", {})
                    print(f"[link] announce: {info.get('server_id')} (from {announcer})")
            # (Optional) re-dial announced id if present in BOOTSTRAP and not linked
            # Left simple to keep code compact.

        else:
            print("Unexpected first message:", msg)
            error_msg = make_envelope(
                "ERROR",
                from_id="server",
                to_id=msg.get("from"),
                payload={"reason": "Expected USER_HELLO or SERVER_HELLO_JOIN first"},
            )
            await websocket.send(json.dumps(error_msg))
            await websocket.close()
            return

        async for message in websocket:
            try:
                frame = json.loads(message)
            except Exception as e:
                print("Malformed JSON:", e)
                continue

            print(f"Received: {frame}")
            await handle_frame(frame)

            # ACK only when this websocket is a USER connection (not a server link)
            if user_id is not None:
                sender = frame.get("from", "unknown")
                ack = make_envelope(
                    "ACK",
                    from_id="server",
                    to_id=sender,
                    payload={"msg_ref": frame.get("id", "unknown")},
                )
                await websocket.send(json.dumps(ack))


    except websockets.exceptions.ConnectionClosed:
        pass
    except Exception as e:
        print("Handler exception:", e)
    finally:
        if user_id:
            await cleanup_user(user_id)
        if server_id:
            remove_server(server_id)
            print(f"Server {server_id} disconnected and cleaned up")

# Main 
async def main(test_mode=False):
    if test_mode:
        print("Server running in test mode – no external links")

    async with websockets.serve(handler, HOST, PORT):
        print(f"Server {SERVER_ID} running on ws://{HOST}:{PORT}")

        tasks = []

        # Only schedule persistent peer connectors if NOT in test mode
        if not test_mode:
            for entry in BOOTSTRAP:
                if entry.get("id") and entry["id"] != SERVER_ID:
                    print(f"[boot] scheduling connect to {entry['id']} @ ws://{entry['host']}:{entry['port']}")
                    tasks.append(asyncio.create_task(_connect_to_peer(entry)))

        # Keep server running forever plus background tasks
        await asyncio.gather(*([asyncio.Future()] + tasks))

if __name__ == "__main__":
    asyncio.run(main())
