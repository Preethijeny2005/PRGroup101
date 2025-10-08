# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

# test_public_channel.py
import sys
import os
import asyncio
import contextlib
import json
import pytest
import pytest_asyncio
import websockets

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from socp import server

HOST = "127.0.0.1"
PORT = 8765

@pytest_asyncio.fixture
async def running_server():
    server_task = asyncio.create_task(server.main(test_mode=True))
    await asyncio.sleep(1.0)
    yield server_task
    server_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await server_task

@pytest.mark.asyncio
async def test_server_starts(running_server):
    # Just connect and disconnect to ensure the server is alive
    uri = f"ws://{HOST}:{PORT}"
    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({"type": "PING"}))
        msg = await ws.recv()
        assert msg is not None
