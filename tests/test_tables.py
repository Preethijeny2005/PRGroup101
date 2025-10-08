# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import pytest
import asyncio
import json
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "socp")))

import socp.tables as tables


class DummyWebSocket:
    def __init__(self):
        self.sent = []

    async def send(self, msg):
        self.sent.append(json.loads(msg))


@pytest.mark.asyncio
async def test_route_to_local_user():
    # Setup: register local user
    ws = DummyWebSocket()
    user_id = "alice"
    tables.local_users[user_id] = ws
    tables.user_locations[user_id] = "local"

    frame = {
        "id": "msg1",
        "from": "bob",
        "to": "alice",
        "type": "TEXT",
        "payload": {"text": "hi"}
    }

    await tables.route_to_user(frame)

    assert len(ws.sent) == 1
    assert ws.sent[0]["payload"]["text"] == "hi"


@pytest.mark.asyncio
async def test_route_to_remote_user():
    # Setup: remote user lives on serverX
    ws_server = DummyWebSocket()
    tables.servers["serverX"] = ws_server
    tables.user_locations["charlie"] = "serverX"

    frame = {
        "id": "msg2",
        "from": "bob",
        "to": "charlie",
        "type": "TEXT",
        "payload": {"text": "yo"}
    }

    await tables.route_to_user(frame)

    assert len(ws_server.sent) == 1
    assert ws_server.sent[0]["to"] == "charlie"


@pytest.mark.asyncio
async def test_loop_suppression():
    # Setup: local user
    ws = DummyWebSocket()
    tables.local_users["dave"] = ws
    tables.user_locations["dave"] = "local"

    frame = {
        "id": "msg3",
        "from": "bob",
        "to": "dave",
        "type": "TEXT",
        "payload": {"text": "hello"}
    }

    # First time: should deliver
    await tables.route_to_user(frame)
    assert len(ws.sent) == 1

    # Second time with same msg id: should be suppressed
    await tables.route_to_user(frame)
    assert len(ws.sent) == 1  # still only one
