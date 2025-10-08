# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

"""
poc_replay.py

Purpose:
 - Demonstrates missing replay suppression: the vulnerable handler processes the same message (same id)
   multiple times if it is re-sent, causing duplicate side effects. The "fixed" handler shows the correct
   behavior by using a replay cache.

Key points:
 - Replay attacks occur when the system does not atomically check whether a message id has already been
   observed before performing side effects.
 - Proper fix: have an atomic check-and-add (or lock-protected) replay cache that prevents processing of
   duplicate message IDs for a bounded window.

How to run:
  python poc_replay.py

Expected output (key lines):
 - Vulnerable run: two "[vuln] Processing message id=...: action=..." lines (duplicate processing)
 - Fixed run: first processed, second dropped with "[fixed] Dropping replayed message id=..." line
"""

import uuid

# Simple list capturing processed actions (demonstrative)
processed = []

def handle_message_vuln(frame):
    """
    Vulnerable message handler:
    - Immediately performs the action (appends to 'processed').
    - No replay detection is used.
    """
    print(f"[vuln] Processing message id={frame['id']}: action={frame['action']}")
    processed.append(frame['action'])

class ReplayCache:
    """
    Minimal replay cache demonstration:
    - For production you would use a thread-safe cache with expiry.
    - Here we use a Python set for demonstration; in multithreaded code protect with locks.
    """
    def __init__(self):
        self.seen = set()

    def seen_add(self, mid):
        """
        Check if mid was seen; if not, add it and return False (not seen before).
        If already seen, return True (indicating the frame should be dropped).
        """
        if mid in self.seen:
            return True
        self.seen.add(mid)
        return False

replay = ReplayCache()

def handle_message_fixed(frame):
    """
    Fixed handler:
    - Calls replay.seen_add(frame['id']) before processing; drops replays.
    - Ensures side effects are not executed for duplicate messages.
    """
    if replay.seen_add(frame['id']):
        print(f"[fixed] Dropping replayed message id={frame['id']}")
        return
    print(f"[fixed] Processing message id={frame['id']}: action={frame['action']}")
    processed.append(frame['action'])

def simulate():
    """
    Demonstrates:
    - vulnerable behavior (same frame processed twice),
    - fixed behavior (second duplicate dropped).
    """
    mid = str(uuid.uuid4())
    frame = {'id': mid, 'action': 'create_item'}

    print("[setup] Vulnerable run:")
    handle_message_vuln(frame)

    print("[exploit] Re-send same frame (vulnerable will process again):")
    handle_message_vuln(frame)

    print("\n[fixed run]")
    processed.clear()
    handle_message_fixed(frame)
    print("[fixed] Re-send same frame (should be dropped):")
    handle_message_fixed(frame)

    print("\nsummary processed:", processed)

if __name__ == '__main__':
    simulate()
