# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

"""
poc_presence_poison.py

Purpose:
 - Demonstrates a presence-poisoning exploit where the server accepts a USER_ADVERTISE
   frame without checking the identity of the connection that sent it. The attacker
   can therefore make the server believe the victim is located at the attacker's host.

High-level exploit flow:
 1. A server maintains a mapping `user_locations` that says where to route messages
    for each user_id (e.g., 'victim_user' -> '10.0.0.5:9000').
 2. Vulnerable handler `handle_user_advertise` trusts incoming advertise frames and writes:
       user_locations[user_id] = host
    without verifying the sending connection is authenticated as that user (or that the
    advertise frame is signed by the user).
 3. An attacker sends a USER_ADVERTISE claiming to be 'victim_user' with host '127.0.0.1:9999'.
 4. The server overwrites the mapping and will now route messages for 'victim_user' to attacker host.

How to run:
  python poc_presence_poison.py

Expected output (key lines):
 - initial user_locations: {'victim_user': '10.0.0.5:9000'}
 - Received USER_ADVERTISE ... conn_auth=None
 - user_locations updated: {'victim_user': '127.0.0.1:9999'}
 - route: Message to victim_user would be routed to 127.0.0.1:9999 (attacker)

Mitigation summary:
 - Bind USER_ADVERTISE acceptance to the authenticated session identity (only accept advertise from the
   connection authenticated as that user), OR
 - Require USER_ADVERTISE frames to be signed by the user's private key and verify the signature + timestamp.
"""

# Routing map (simulated)
user_locations = {}

def handle_user_advertise(frame, conn_authenticated_user=None):
    """
    Vulnerable handler:
    - 'frame' is expected to be a dict with keys 'user_id' and 'host'.
    - 'conn_authenticated_user' is the identity that the connection already authenticated as,
      or None if the connection is unauthenticated.

    Vulnerability: the handler does not check that the connection has authenticated as the user it
    claims to represent. It directly updates the routing table from untrusted frame contents.
    """
    uid = frame.get("user_id")
    host = frame.get("host")

    # Print the received frame and the (lack of) authentication context. In a secure implementation
    # conn_authenticated_user would be non-None and equal to uid when the advertise is legitimate.
    print(f"[server] Received USER_ADVERTISE: user_id={uid}, host={host}, conn_auth={conn_authenticated_user}")

    # VULNERABLE: trusting unverified input -> attacker can spoof and overwrite routing
    user_locations[uid] = host
    print(f"[server] user_locations updated: {user_locations}")

def simulate():
    """
    Simulation steps:
      1. Set an initial legitimate mapping for 'victim_user'.
      2. An unauthenticated attacker sends a USER_ADVERTISE claiming 'victim_user'.
      3. Show that user_locations now points to attacker-controlled host.
    """
    user_locations['victim_user'] = "10.0.0.5:9000"
    print("[setup] initial user_locations:", user_locations)

    # Attacker frame (conn_authenticated_user=None shows unauthenticated)
    attacker_frame = {'user_id': 'victim_user', 'host': '127.0.0.1:9999'}
    handle_user_advertise(attacker_frame, conn_authenticated_user=None)

    # Simulate routing a message to victim_user — it will go to the attacker host.
    routed = user_locations.get('victim_user')
    print(f"[route] Message to victim_user would be routed to {routed} (attacker)")

if __name__ == '__main__':
    simulate()
