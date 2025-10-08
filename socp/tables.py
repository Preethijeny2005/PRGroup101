# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import asyncio
import json

# In-memory tables
local_users = {}       # user_id -> websocket
servers = {}           # server_id -> websocket
user_locations = {}    # user_id -> "local" or server_id
seen_ids = set()       # message_ids we've already processed
user_sessions = {}     # user_id -> session_token

# keep seen_ids cleanup placeholder
_seen_ids_lock = asyncio.Lock()
_seen_ids_max = 100000

# Public channel state (Milestone 5)
public_members: set[str] = set()             # user_ids in the public channel
public_version: int = 1                      # bump whenever membership changes
public_wraps: dict[str, str] = {}            # member_id -> b64url(wrapped_channel_key_material)
channel_pub_b64: str | None = None           # b64url DER SubjectPublicKeyInfo (RSA-4096)
channel_priv_bytes: bytes | None = None      # DER PKCS#8 (keep only in memory at this milestone)

async def _maybe_cleanup_seen_ids():
    """Very simple heuristic: if the set grows too large, clear it."""
    global seen_ids
    async with _seen_ids_lock:
        if len(seen_ids) > _seen_ids_max:
            seen_ids.clear()

async def route_to_user(frame: dict):
    """
    Route a message to its destination user using in-memory tables.
    Assumes frame has keys: "id" (msg_id), "to" (user_id), "from", "type", "payload"
    """
    await _maybe_cleanup_seen_ids()

    msg_id = frame.get("id")
    if not msg_id:
        print("Dropping frame with no id:", frame)
        return

    # Loop suppression
    if msg_id in seen_ids:
        print(f"Skipping already-seen message {msg_id}")
        return
    seen_ids.add(msg_id)

    uid = frame.get("to")
    if not uid:
        print("Dropping frame with no target:", frame)
        return

    # Local delivery
    if uid in local_users:
        ws = local_users[uid]
        try:
            await ws.send(json.dumps(frame))
            print(f"[route] sent {frame.get('type')} {msg_id} to LOCAL user {uid}")
        except Exception as e:
            print(f"[route] error sending to local user {uid}: {e}")
        return

    # Remote delivery
    host = user_locations.get(uid)
    if not host:
        print(f"[route] no host for user {uid}, drop {msg_id}")
        return

    ws = servers.get(host)
    if not ws:
        print(f"[route] no ws to host {host} for user {uid}, drop {msg_id}")
        return

    try:
        await ws.send(json.dumps(frame))
        print(f"[route] sent {frame.get('type')} {msg_id} for {uid} -> {host}")
    except Exception as e:
        print(f"[route] error sending {msg_id} for {uid} -> {host}: {e}")


# Helper functions for session management
def set_user_session(user_id: str, session_token: str):
    """Assign a session token to a user"""
    user_sessions[user_id] = session_token

def get_user_session(user_id: str) -> str | None:
    """Return the current session token for a user, or None if not set"""
    return user_sessions.get(user_id)

def remove_user_session(user_id: str):
    """Remove a user's session token"""
    if user_id in user_sessions:
        del user_sessions[user_id]

def remove_server(server_id: str):
    """Remove a server and any user mappings pointing to it."""
    if server_id in servers:
        del servers[server_id]
    for u, loc in list(user_locations.items()):
        if loc == server_id:
            del user_locations[u]
