# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import asyncio
import websockets
import json
import os
import uuid
from datetime import datetime, timezone
import hashlib  # <-- NEW: for sha256 hex

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from socp.crypto import (
    sign_bytes,
    load_private_key_pem,
    import_public_base64url,
    generate_rsa4096,
    save_private_key_pem,
    export_public_base64url,
    verify_bytes,
)
from socp.utils import (
    json_canonicalize,
    make_envelope,
    now_ts_iso,
    b64url_encode_no_padding,
    b64url_decode_no_padding,
)

# Config
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8765"))

PUBLIC_KEYS_DIR = "keys/public"
DOWNLOADS_DIR = "downloads"

# In-flight received files: file_id -> {name,size,sha256,mode,from,to,chunks:{}}
_rx_files = {}

# Runtime state
ws_connection = None
user_name = None
privkey = None

# Public channel cache
_channel_priv = None          # RSAPrivateKey (unwrapped channel private key)
_channel_pub_b64 = None       # base64url DER SPKI (encrypt /all)

# UI gate so we only show commands once when fully ready 
_ui_ready_printed = False

# print options
def _print_options():
    print("Commands: connect <name>, tell <user> <msg>, all <msg>, list, "
          "sendfile <user> <path>, sendpub <path>, quit")
    print("> ", end="", flush=True)

def _maybe_print_ready_options():
    """Print options once when both channel pub + priv are ready."""
    global _ui_ready_printed, _channel_pub_b64, _channel_priv
    if not _ui_ready_printed and _channel_pub_b64 and _channel_priv:
        _ui_ready_printed = True
        _print_options()

# for announcing to the server the client is here
def _build_user_hello():
    """
    Create a spec-compliant USER_HELLO with pubkey(s), timestamp, 'to', and a top-level signature.
    """
    global user_name, privkey
    ts = int(datetime.now(timezone.utc).timestamp() * 1000)
    server_id = f"server@{HOST}:{PORT}"  # matches server.py's SERVER_ID

    pub_b64 = export_public_base64url(privkey.public_key())
    payload = {
        "client": "cli-v1",
        "pubkey": pub_b64,
        "enc_pubkey": pub_b64,  # same as pubkey for now (no separate enc key yet)
    }

    env = {
        "id": str(uuid.uuid4()),
        "type": "USER_HELLO",
        "from": user_name,
        "to": server_id,
        "ts": ts,
        "payload": payload,
        # "sig": added below
    }

    # Sign canonicalized envelope (without sig) with the user's private key
    canon = json_canonicalize(env).encode("utf-8")
    env["sig"] = b64url_encode_no_padding(sign_bytes(privkey, canon))
    return env

# Key utilities
def ensure_keys_for_user(username: str):
    """
    Load existing or generate a new RSA-4096 keypair for the given username.
    Private key saved to keys/private_<username>.pem (PEM PKCS8).
    Public key exported as base64url(DER) to keys/public/<username>.pub.
    """
    os.makedirs(PUBLIC_KEYS_DIR, exist_ok=True)
    keys_root = os.path.dirname(PUBLIC_KEYS_DIR) or "."
    if not os.path.exists(keys_root):
        os.makedirs(keys_root, exist_ok=True)

    priv_path = os.path.join(keys_root, f"private_{username}.pem")
    pub_path = os.path.join(PUBLIC_KEYS_DIR, f"{username}.pub")

    if os.path.exists(priv_path):
        priv = load_private_key_pem(priv_path)
        if not os.path.exists(pub_path):
            pub = priv.public_key()
            with open(pub_path, "w") as f:
                f.write(export_public_base64url(pub))
        return priv

    priv, pub = generate_rsa4096()
    save_private_key_pem(priv, priv_path)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    with open(pub_path, "w") as f:
        f.write(export_public_base64url(pub))
    return priv

def load_recipient_pubkey(username: str) -> RSAPublicKey:
    path = os.path.join(PUBLIC_KEYS_DIR, f"{username}.pub")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Recipient key for '{username}' not found")
    with open(path, "r") as f:
        b64u = f.read().strip()
    return import_public_base64url(b64u)

# Helpers: unwrap channel private key package (AES-GCM + RSA-OAEP wrapped AES key)
def _unwrap_channel_priv_package(package_b64u: str):
    global _channel_priv
    try:
        data = b64url_decode_no_padding(package_b64u)
        obj = json.loads(data.decode("utf-8"))
        if obj.get("alg") != "A256GCM+RSAOAEP":
            raise ValueError("Unknown alg in wrapped_key")
        iv = b64url_decode_no_padding(obj["iv"])
        ek = b64url_decode_no_padding(obj["ek"])
        ct = b64url_decode_no_padding(obj["ct"])

        # RSA-OAEP unwrap AES key using user's private key
        aes_key = privkey.decrypt(
            ek,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        aead = AESGCM(aes_key)
        priv_bytes = aead.decrypt(iv, ct, None)
        new_priv = load_der_private_key(priv_bytes, password=None)
        is_first_unwrap = (_channel_priv is None)
        _channel_priv = new_priv
        if is_first_unwrap:
            #print("[public] channel private key unwrapped; you can now /all (read)")
            _drain_pending_public()
            _maybe_print_ready_options()
    except Exception as e:
        print(f"[public] unwrap failed: {e}")

# Direct-message encrypt/sign helper
def encrypt_message(to_user: str, plaintext: str) -> dict:
    global user_name, privkey
    if not user_name:
        raise ValueError("Connect before sending messages.")
    if not to_user:
        raise ValueError("Recipient username required.")
    if not plaintext:
        raise ValueError("Message cannot be empty.")

    pubkey = load_recipient_pubkey(to_user)
    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = pubkey.encrypt(
        plaintext_bytes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    ts = int(datetime.now(timezone.utc).timestamp() * 1000)
    user_bytes = str(user_name).encode("utf-8")
    to_bytes = str(to_user).encode("utf-8")
    ts_bytes = str(ts).encode("utf-8")

    sig_data = ciphertext + user_bytes + to_bytes + ts_bytes
    content_sig = sign_bytes(privkey, sig_data)
    sender_pub_b64 = export_public_base64url(privkey.public_key())

    return {
        "ciphertext": b64url_encode_no_padding(ciphertext),
        "content_sig": b64url_encode_no_padding(content_sig),
        "sender_pub": sender_pub_b64,
        "from": str(user_name),
        "to": str(to_user),
        "ts": ts,
    }

# Public channel: /all sender (encrypt to channel_pub, sign digest)
def cmd_all(text: str, ws):
    global _channel_pub_b64, user_name, privkey
    if not _channel_pub_b64:
        #print("[public] no channel_pub yet; wait for PUBLIC_CHANNEL_KEY_SHARE/UPDATED")
        return

    ch_pub = import_public_base64url(_channel_pub_b64)
    pt = text.encode("utf-8")
    ct = ch_pub.encrypt(
        pt,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    ct_b64 = b64url_encode_no_padding(ct)

    ts = int(datetime.now(timezone.utc).timestamp() * 1000)

    # Signature over SHA256(ciphertext|from|ts)
    from hashlib import sha256
    h = sha256()
    h.update(ct)
    h.update(user_name.encode("utf-8"))
    h.update(str(ts).encode("utf-8"))
    digest = h.digest()
    sig_b64 = b64url_encode_no_padding(sign_bytes(privkey, digest))

    frame = {
        "type": "MSG_PUBLIC_CHANNEL",
        "from": user_name,
        "to": "public",
        "id": f"pub-{ts}",
        "ts": ts,
        "payload": {
            "ciphertext": ct_b64,
            "sender_pub": export_public_base64url(privkey.public_key()),
            "content_sig": sig_b64,
        },
    }
    # Optional top-level signature over canonicalized envelope (without sig)
    try:
        canon = json_canonicalize(frame).encode("utf-8")
        frame["sig"] = b64url_encode_no_padding(sign_bytes(privkey, canon))
    except Exception:
        pass

    asyncio.create_task(ws.send(json.dumps(frame)))

# 9.4: File Transfer (Sender side) 
def _rsa_oaep_max_plaintext(pub: RSAPublicKey) -> int:
    # For OAEP with SHA-256: max = k - 2*hLen - 2
    k = pub.key_size // 8
    hlen = hashes.SHA256().digest_size
    return max(0, k - 2 * hlen - 2)

async def _send_file_manifest(mode: str, to_field: str, path: str):
    """Send FILE_START manifest (spec §9.4). Returns (file_id, size, sha_hex, data_bytes)."""
    global user_name, ws_connection
    if not os.path.isfile(path):
        #print(f"[file] not found: {path}")
        return None

    with open(path, "rb") as f:
        data = f.read()

    size = len(data)
    sha_hex = hashlib.sha256(data).hexdigest()
    file_id = str(uuid.uuid4())
    ts = int(datetime.now(timezone.utc).timestamp() * 1000)

    start_frame = {
        "type": "FILE_START",
        "from": user_name,
        "to": to_field,
        "ts": ts,
        "payload": {
            "file_id": file_id,
            "name": os.path.basename(path),
            "size": size,
            "sha256": sha_hex,
            "mode": mode,  # "dm" or "public"
        },
        # "sig": optional
    }
    await ws_connection.send(json.dumps(start_frame))
    print(f"[file] START → {to_field}  id={file_id}  name={os.path.basename(path)}  size={size}")
    return file_id, size, sha_hex, data

async def _send_file_chunks_dm(to_user: str, file_id: str, data: bytes):
    """Encrypt each chunk with recipient's RSA-OAEP(SHA-256) and send FILE_CHUNK frames."""
    global ws_connection
    pub = load_recipient_pubkey(to_user)
    max_pt = _rsa_oaep_max_plaintext(pub)
    chunk_size = min(400, max_pt)  # conservative to avoid edge cases
    idx = 0
    for off in range(0, len(data), chunk_size):
        pt = data[off: off + chunk_size]
        ct = pub.encrypt(
            pt,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        frame = {
            "type": "FILE_CHUNK",
            "from": user_name,
            "to": to_user,
            "ts": int(datetime.now(timezone.utc).timestamp() * 1000),
            "payload": {
                "file_id": file_id,
                "index": idx,
                "ciphertext": b64url_encode_no_padding(ct),
            },
        }
        await ws_connection.send(json.dumps(frame))
        idx += 1
    print(f"[file] CHUNKS sent ({idx}) for id={file_id} to {to_user}")

async def _send_file_chunks_public(file_id: str, data: bytes):
    """Encrypt each chunk with channel public key and send FILE_CHUNK frames to 'public'."""
    global ws_connection, _channel_pub_b64
    if not _channel_pub_b64:
        print("[file] public channel key not ready; connect and wait for KEY_SHARE/UPDATED first")
        return
    ch_pub = import_public_base64url(_channel_pub_b64)
    max_pt = _rsa_oaep_max_plaintext(ch_pub)
    chunk_size = min(400, max_pt)
    idx = 0
    for off in range(0, len(data), chunk_size):
        pt = data[off: off + chunk_size]
        ct = ch_pub.encrypt(
            pt,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        frame = {
            "type": "FILE_CHUNK",
            "from": user_name,
            "to": "public",
            "ts": int(datetime.now(timezone.utc).timestamp() * 1000),
            "payload": {
                "file_id": file_id,
                "index": idx,
                "ciphertext": b64url_encode_no_padding(ct),
            },
        }
        await ws_connection.send(json.dumps(frame))
        idx += 1
    print(f"[file] CHUNKS sent ({idx}) for id={file_id} to public")

async def _send_file_end(to_field: str, file_id: str):
    """Send FILE_END (spec §9.4)."""
    global ws_connection
    frame = {
        "type": "FILE_END",
        "from": user_name,
        "to": to_field,
        "ts": int(datetime.now(timezone.utc).timestamp() * 1000),
        "payload": {"file_id": file_id},
    }
    await ws_connection.send(json.dumps(frame))
    print(f"[file] END → {to_field}  id={file_id}")

# file transfer reconstructing in downloads folder
def _ensure_download_dir() -> str:
    d = os.path.join(DOWNLOADS_DIR, user_name or "unknown")
    os.makedirs(d, exist_ok=True)
    return d

def _safe_output_path(name: str, file_id: str) -> str:
    d = _ensure_download_dir()
    out = os.path.join(d, name)
    if os.path.exists(out):
        base, ext = os.path.splitext(name)
        out = os.path.join(d, f"{base}-{file_id}{ext}")
    return out

# public file sending helpers
def _finalize_and_save(file_id: str) -> bool:
    rec = _rx_files.get(file_id)
    if not rec:
        return False
    # Reassemble in order
    try:
        data = b"".join(rec["chunks"][i] for i in sorted(rec["chunks"].keys()))
    except KeyError:
        return False

    size_ok = (len(data) == rec["size"])
    sha_hex = hashlib.sha256(data).hexdigest()
    sha_ok = (rec["sha256"] == sha_hex)
    if not (size_ok and sha_ok):
        return False

    out_path = _safe_output_path(rec["name"], file_id)
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"[file] wrote → {out_path} ({len(data)} bytes)")
    print(f"[file] size_ok={size_ok} sha_ok={sha_ok} (expected={rec['sha256']} got={sha_hex})")
    del _rx_files[file_id]
    return True


def _drain_pending_public():
    """When the public channel private key arrives, decrypt any buffered ciphertext chunks."""
    if not _channel_priv:
        return
    for fid, rec in list(_rx_files.items()):
        if rec.get("mode") != "public":
            continue
        pend = rec.get("pending_ct") or {}
        if not pend:
            continue
        for i, ct in list(pend.items()):
            try:
                pt = _channel_priv.decrypt(
                    ct,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                rec["chunks"][int(i)] = pt
                del pend[i]
            except Exception as e:
                print(f"[file] pending decrypt failed for id={fid} idx={i}: {e}")
        # If everything is here now, finalize
        _finalize_and_save(fid)

# Receiver
async def listen(ws):
    global _channel_priv, _channel_pub_b64, user_name
    async for message in ws:
        msg = json.loads(message)
        msg_type = msg.get("type")
        payload = msg.get("payload", {})

        if msg_type == "PUBLIC_CHANNEL_UPDATED":
            version = payload.get("version")
            wraps = payload.get("wraps", [])
            members = [w.get("member_id") for w in wraps]
            #print(f"[public] channel updated: version={version}, members={members}")
            mine = next((w for w in wraps if w.get("member_id") == user_name and w.get("wrapped_key")), None)
            if mine and privkey and _channel_priv is None:
                _unwrap_channel_priv_package(mine["wrapped_key"])

        elif msg_type == "PUBLIC_CHANNEL_KEY_SHARE":
            creator_pub_b64 = payload.get("creator_pub")
            shares = payload.get("shares", [])
            content_sig_b64 = payload.get("content_sig", "")
            try:
                pub = import_public_base64url(creator_pub_b64)
                signed_bytes = json_canonicalize({"shares": shares, "creator_pub": creator_pub_b64}).encode("utf-8")
                if not verify_bytes(pub, signed_bytes, b64url_decode_no_padding(content_sig_b64)):
                    print("[public] KEY_SHARE content_sig verify FAILED")
                else:
                    #print("[public] channel pubkey received (creator_pub); you can now /all")
                    _channel_pub_b64 = creator_pub_b64
                    _maybe_print_ready_options()
            except Exception as e:
                print(f"[public] key-share verify error: {e}")

            mine = next((s for s in shares if s.get("member") == user_name), None)
            if mine and "wrapped_public_channel_key" in mine:
                _unwrap_channel_priv_package(mine["wrapped_public_channel_key"])

        elif msg_type == "USER_DELIVER":
            # DM first (has 'from' and 'to' inside payload)
            pl = payload
            if "from" in pl and "to" in pl:
                sender = pl.get("from")
                if not sender:
                    continue
                ciphertext = b64url_decode_no_padding(pl.get("ciphertext", ""))
                content_sig = b64url_decode_no_padding(pl.get("content_sig", ""))
                ts = pl.get("ts") or int(datetime.now(timezone.utc).timestamp() * 1000)

                sender_bytes = str(sender).encode("utf-8")
                user_bytes = str(user_name).encode("utf-8")
                ts_bytes = str(ts).encode("utf-8")

                try:
                    plaintext = privkey.decrypt(
                        ciphertext,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                    ).decode("utf-8")
                except Exception as e:
                    print(f"\rFailed to decrypt message from {sender}: {e}")
                    print("> ", end="", flush=True)
                    continue

                sig_data = ciphertext + sender_bytes + user_bytes + ts_bytes
                try:
                    sender_pub_b64 = pl.get("sender_pub")
                    if sender_pub_b64:
                        sender_pubkey = import_public_base64url(sender_pub_b64)
                    else:
                        sender_pubkey = load_recipient_pubkey(sender)

                    sender_pubkey.verify(
                        content_sig,
                        sig_data,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256(),
                    )
                    verified = True
                except InvalidSignature:
                    verified = False
                except Exception:
                    verified = False

                status = "Verified" if verified else "Unverified"
                print(f"\r[Message from {sender} [{status}]] {plaintext}")
                print("> ", end="", flush=True)
                continue

            # Public branch
            if "ciphertext" in pl and "sender_pub" in pl and "content_sig" in pl:
                try:
                    sender_pub = import_public_base64url(pl["sender_pub"])
                    ct = b64url_decode_no_padding(pl["ciphertext"])
                    sig = b64url_decode_no_padding(pl["content_sig"])
                    from_id = msg.get("from", "?")
                    ts = msg.get("ts") or 0

                    from hashlib import sha256
                    h = sha256()
                    h.update(ct)
                    h.update(from_id.encode("utf-8"))
                    h.update(str(ts).encode("utf-8"))
                    if not verify_bytes(sender_pub, h.digest(), sig):
                        print("[public] content_sig verify FAILED")
                        print("> ", end="", flush=True)
                        continue

                    if not _channel_priv:
                        print("[public] no channel private key yet; cannot decrypt")
                        print("> ", end="", flush=True)
                        continue

                    pt = _channel_priv.decrypt(
                        ct,
                        asym_padding.OAEP(
                            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    print(f"\r[public] {from_id}: {pt.decode('utf-8', 'replace')}")
                    print("> ", end="", flush=True)
                except Exception as e:
                    print(f"\r[public] error: {e}")
                    print("> ", end="", flush=True)
                continue

        # 9.4: File Transfer receive-side (decrypt, assemble, save) 
        elif msg_type in ("FILE_START", "FILE_CHUNK", "FILE_END"):
            pl = payload or {}

            if msg_type == "FILE_START":
                file_id = pl.get("file_id")
                if not file_id:
                    print("\r[file] START missing file_id")
                    print("> ", end="", flush=True)
                    continue
                # when handling FILE_START (in listen)
                _rx_files[file_id] = {
                    "from": msg.get("from"),
                    "to": msg.get("to"),
                    "name": pl.get("name", f"unnamed-{file_id}"),
                    "size": int(pl.get("size", 0) or 0),
                    "sha256": (pl.get("sha256") or "").lower(),
                    "mode": pl.get("mode", "dm"),
                    "chunks": {},        # index -> plaintext bytes
                    "pending_ct": {},    # index -> ciphertext bytes (public chunks when key not ready)
                }
                print(f"\r[file] START from {msg.get('from')} → {msg.get('to')}: "
                      f"{_rx_files[file_id]['name']} ({_rx_files[file_id]['size']} bytes) "
                      f"id={file_id} mode={_rx_files[file_id]['mode']}")
                print("> ", end="", flush=True)
                continue

            if msg_type == "FILE_CHUNK":
                file_id = pl.get("file_id")
                index = pl.get("index")
                ct_b64 = pl.get("ciphertext")
                rec = _rx_files.get(file_id)
                if rec is None:
                    print(f"\r[file] CHUNK for unknown id={file_id} (START not seen yet)")
                    print("> ", end="", flush=True)
                    continue

                try:
                    # when handling FILE_CHUNK (in listen)
                    ct = b64url_decode_no_padding(ct_b64)
                    if rec["mode"] == "public":
                        if not _channel_priv:
                            # Key not here yet → buffer the ciphertext
                            rec["pending_ct"][int(index)] = ct
                            print(f"\r[file] CHUNK #{index} buffered (waiting for channel key) for id={file_id}")
                        else:
                            pt = _channel_priv.decrypt(
                                ct,
                                asym_padding.OAEP(
                                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )
                            rec["chunks"][int(index)] = pt
                            print(f"\r[file] CHUNK #{index} for id={file_id}")
                    else:  # dm
                        pt = privkey.decrypt(
                            ct,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )
                        rec["chunks"][int(index)] = pt
                        print(f"\r[file] CHUNK #{index} for id={file_id}")
                except Exception as e:
                    print(f"\r[file] CHUNK decrypt error for id={file_id} idx={index}: {e}")
                print("> ", end="", flush=True)
                continue

            if msg_type == "FILE_END":
                file_id = pl.get("file_id")
                rec = _rx_files.get(file_id)
                if rec is None:
                    print(f"\r[file] END for unknown id={file_id}")
                    print("> ", end="", flush=True)
                    continue

                # If it's public and we now have the key, try to decrypt any buffered chunks first
                if rec["mode"] == "public" and _channel_priv and rec.get("pending_ct"):
                    for i, ct in list(rec["pending_ct"].items()):
                        try:
                            pt = _channel_priv.decrypt(
                                ct,
                                asym_padding.OAEP(
                                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )
                            rec["chunks"][int(i)] = pt
                            del rec["pending_ct"][i]
                        except Exception as e:
                            print(f"[file] pending decrypt failed for id={file_id} idx={i}: {e}")

                print(f"\r[file] END for id={file_id}")

                # Finalize ONLY if size/hash are correct
                ok = _finalize_and_save(file_id)
                if not ok:
                    have = len(rec["chunks"])
                    pending = len(rec.get("pending_ct", {}))
                    print(f"[file] INCOMPLETE/INVALID; not saved. have_chunks={have} pending={pending} expected_size={rec['size']}")
                    # If we’re still waiting on the public key or pending ciphertext, keep it in memory; else drop.
                    if not (rec["mode"] == "public" and (not _channel_priv or rec.get("pending_ct"))):
                        del _rx_files[file_id]

                print("> ", end="", flush=True)
                continue

        elif msg_type == "WHO":
            users = payload.get("users", [])
            print(f"\rOnline users: {', '.join(users)}")
            print("> ", end="", flush=True)

        elif msg_type == "ERROR":
            print(f"\r[server ERROR] {payload.get('reason','unknown error')}")
            print("> ", end="", flush=True)

# Command loop
async def command_loop():
    global ws_connection, user_name, privkey
    # print("SOCP client ready. Commands: connect <name>, tell <user> <msg>, all <msg>, list, "
    #       "sendfile <user> <path>, sendpub <path>, quit")
    print("SOCP client ready. Type: connect <name>")

    while True:
        cmd = (await asyncio.to_thread(input, "> ")).strip()

        if cmd.startswith("connect "):
            user_name = cmd.split(" ", 1)[1].strip()
            try:
                privkey = ensure_keys_for_user(user_name)
            except Exception as e:
                print(f"Failed to ensure keys for user {user_name}: {e}")
                continue

            ws_connection = await websockets.connect(f"ws://{HOST}:{PORT}")
            asyncio.create_task(listen(ws_connection))   # start listen first
            hello_msg = _build_user_hello()
            await ws_connection.send(json.dumps(hello_msg))
            print(f"Connected as {user_name}")
            # reset readiness gate for this session
            global _ui_ready_printed
            _ui_ready_printed = False

        elif cmd.startswith("tell "):
            if not ws_connection or not user_name:
                print("Not connected. Use: connect <name>")
                continue
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Usage: tell <user> <message>")
                continue
            to_user, text = parts[1], parts[2]
            payload = encrypt_message(to_user, text)
            envelope = {
                "id": str(uuid.uuid4()),
                "type": "MSG_DIRECT",
                "from": user_name,
                "to": to_user,
                "ts": int(datetime.now(timezone.utc).timestamp() * 1000),
                "payload": payload,
            }
            try:
                env_canon = json_canonicalize(envelope).encode("utf-8")
                link_sig = sign_bytes(privkey, env_canon)
                envelope["sig"] = b64url_encode_no_padding(link_sig)
            except Exception:
                pass

            await ws_connection.send(json.dumps(envelope))
            print(f"[{user_name} -> {to_user}] (encrypted) {text}")

        elif cmd.startswith("all "):
            if not ws_connection or not user_name:
                print("Not connected. Use: connect <name>")
                continue
            text = cmd.split(" ", 1)[1]
            cmd_all(text, ws_connection)

        # 9.4: File Transfer commands
        elif cmd.startswith("sendfile "):
            # DM: sendfile <user> <path>
            if not ws_connection or not user_name:
                print("Not connected. Use: connect <name>")
                continue
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Usage: sendfile <user> <path>")
                continue
            to_user, path = parts[1], parts[2]
            mf = await _send_file_manifest("dm", to_user, path)
            if not mf:
                continue
            file_id, _size, _sha, data = mf
            await _send_file_chunks_dm(to_user, file_id, data)
            await _send_file_end(to_user, file_id)

        elif cmd.startswith("sendpub "):
            # Public: sendpub <path>
            if not ws_connection or not user_name:
                print("Not connected. Use: connect <name>")
                continue
            parts = cmd.split(" ", 1)
            if len(parts) < 2:
                print("Usage: sendpub <path>")
                continue
            path = parts[1]
            mf = await _send_file_manifest("public", "public", path)
            if not mf:
                continue
            file_id, _size, _sha, data = mf
            await _send_file_chunks_public(file_id, data)
            await _send_file_end("public", file_id)

        elif cmd == "list":
            if not ws_connection or not user_name:
                print("Not connected. Use: connect <name>")
                continue
            who_msg = {"type": "WHO", "from": user_name, "id": str(datetime.now(timezone.utc).timestamp()), "payload": {}}
            await ws_connection.send(json.dumps(who_msg))

        elif cmd == "quit":
            if ws_connection:
                await ws_connection.close()
            print("Bye!")
            return

        else:
            print("Commands: connect <name>, tell <user> <msg>, all <msg>, list, "
                  "sendfile <user> <path>, sendpub <path>, quit")

# Main
async def main():
    await command_loop()

if __name__ == "__main__":
    asyncio.run(main())
