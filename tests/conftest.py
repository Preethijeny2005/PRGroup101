# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import sys
import os
import asyncio
import contextlib

# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest_asyncio
from socp import server

HOST = "127.0.0.1"
PORT = 8765

@pytest_asyncio.fixture
async def running_server():
    """
    Starts the WebSocket server in the background and keeps it alive for tests.
    """
    # Run server in background task
    server_task = asyncio.create_task(server.main(test_mode=True))

    # Wait for server to bind
    await asyncio.sleep(1)

    # Yield control to test
    yield

    # Teardown: cancel server task
    server_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await server_task
