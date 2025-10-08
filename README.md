# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

## Project Goal
This repository contains a Python implementation of the **Secure Overlay Chat Protocol (SOCP v1.3)**.  
The goal is to build a fully compliant server and client that support:  

- End-to-end encrypted **direct messaging** (DMs)  
- **Public channel messaging** with group key distribution  
- **File transfers** (DM or public channel)  
- **Server-to-server bootstrapping and gossip** for user presence  
- **Routing algorithm** with duplicate suppression  
- Mandatory features: `/list`, `/tell`, `/all`, `/file`  
- A compliance checklist as defined in the official SOCP specification  

This implementation will be developed step by step (Milestones 0–10), starting with a basic WebSocket server and extending to cryptography, routing, and persistence.  

---

## Setup (Virtual Environment)

It’s recommended to use a **virtual environment** so dependencies are isolated from your system Python.  
You can use either `venv` (standard library) or Poetry — this guide uses `venv`.

### 1. Clone the repository
```bash
git clone <repo-url>
cd python
```
### 2. Create and activate the virtual environment

(Python version 3.10.12)

```bash
python3 -m venv .venv
source .venv/bin/activate   # On Linux/Mac
.venv\Scripts\activate      # On Windows (PowerShell)
```

### 3. Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
### 4. Run tests to confirm setup
```bash
pytest
```

### 5. Running a server
In one terminal (server):
```bash
python -m socp.server
``

To connect in another terminal run (client):
```bash
python -m socp.client
```

### 5.1 Running multi servers
In terminal find pubkey values:
```bash
KEYS_DIR=keysA SERVER_ID=127.0.0.1:8765 PORT=8765 python - <<'PY'
from socp.crypto import load_private_key_pem, export_public_base64url; 
print(export_public_base64url(load_private_key_pem('keysA/server_private.pem').public_key()))
PY
``
paste output into srvA pubkey inside config.ymal


In terminal find pubkey values:
```bash
KEYS_DIR=keysB SERVER_ID=127.0.0.1:8870 PORT=8870 python - <<'PY'
from socp.crypto import load_private_key_pem, export_public_base64url; 
print(export_public_base64url(load_private_key_pem('keysB/server_private.pem').public_key()))
PY
``
paste output into srvB pubkey inside config.ymal


In terminal 1:
```bash
KEYS_DIR=keysA SERVER_ID=127.0.0.1:8765 HOST=127.0.0.1 PORT=8765 python -m socp.server
``


In terminal 2:
```bash
KEYS_DIR=keysB SERVER_ID=127.0.0.1:8870 HOST=127.0.0.1 PORT=8870 python -m socp.server
``


To connect client in terminal 3:
```bash
SERVER_ID=127.0.0.1:8765 HOST=127.0.0.1 PORT=8765 python -m socp.client
```


To connect client in terminal 4:
```bash
SERVER_ID=127.0.0.1:8870 HOST=127.0.0.1 PORT=8870 python -m socp.client
```


To chat on the server):
```bash
> connect <username>
> list (list all online users)
> tell <reciever> <message>
> quit (leave cleanly)
```

# Database Setup Instructions

This section explains how to install MySQL, create a database and user, and prepare it for running the project’s Python scripts.

---

## 1. Install MySQL Server

### Ubuntu / Debian
```bash
sudo apt update
sudo apt install mysql-server -y
sudo systemctl start mysql
sudo systemctl enable mysql
```

### macOS (Homebrew)
```bash
brew install mysql
brew services start mysql
```

### Windows
1. Download MySQL Installer from [MySQL Downloads](https://dev.mysql.com/downloads/installer/).  
2. Run the installer and select “Server Only” or “Custom”.  
3. Set a root password and configure MySQL as a service.

---

## 2. Log in to MySQL

### Linux (Debian/Ubuntu)
```bash
# Logs in as root via auth_socket (no password needed)
sudo mysql
```

### macOS / Windows
```bash
# Logs in as root; will prompt for the password you set during installation
mysql -u root -p
```

> Note: On Linux, if you prefer password authentication for root, you can set one with:
```sql
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'yourpassword';
FLUSH PRIVILEGES;
```
Then you can use `mysql -u root -p` as on macOS/Windows.

---

## 3. Create Database and User

Replace `chatdb` and `yourpassword` with your preferred database name and password.

```sql
-- Create the database
CREATE DATABASE IF NOT EXISTS chatdb;

-- Create a dedicated user
CREATE USER 'chat_user'@'127.0.0.1' IDENTIFIED BY 'yourpassword';

-- Grant privileges
GRANT ALL PRIVILEGES ON chatdb.* TO 'chat_user'@'127.0.0.1';
FLUSH PRIVILEGES;
quit
```

> Optional: If you prefer to use root, ensure `DB_CONFIG` in your Python code uses `"user": "root"` and the corresponding password.

---

## 4. Verify Connection

```bash
mysql -u chat_user -p -h 127.0.0.1 chatdb
```

You should be able to log in without errors.

---

## 5. Run Database Initialization Script

Once the database is set up and accessible, run the Python script to create tables and insert initial data:

```bash
python -m socp.db
```

This will:
- Create the tables (`users`, `public_channel`, `public_members`)  
- Insert the default `public` channel  
- Allow your application to start using the database

---

## 6. Update Python `DB_CONFIG`

Make sure `DB_CONFIG` in your project matches the credentials:

```python
DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "chat_user",         
    "password": "yourpassword",
    "db": "chatdb"
}
```

> Ensure the host and port match your MySQL server configuration.

## 7. Start or Ensure MySQL Server is Running

Before running your Python scripts, make sure MySQL is active. Use the commands for your platform:

### Linux (systemd)
```bash
sudo systemctl start mysql    # Start MySQL
sudo systemctl enable mysql   # Ensure it starts on boot
sudo systemctl status mysql   # Check status
```

### macOS (Homebrew)
```bash
brew services start mysql     # Start MySQL
brew services list            # Verify status
```

### Windows
1. Open **Services** (`Win + R`, type `services.msc`)  
2. Find `MySQL` or `MySQL80` → Status should be **Running**  
3. Right-click → **Start** if not running  

### Quick Cross-Platform Check
You can also test if MySQL is running by trying to ping it from the terminal:

```bash
mysqladmin ping -u root -p
```
- Output `mysqld is alive` → server is running

---

## Ethical backdoor/vulnerability (BELOW IS FOR MARKERS ONLY)

## Files (PoC scripts)
All PoC scripts are located in the poc/ directory:
poc/poc_presence_poison.py — presence poisoning via unauthenticated USER_ADVERTISE.
poc/poc_replay.py — missing duplicate-message suppression (replay acceptance).
poc/poc_weak_rsa.py — accepting weak RSA key parameters (1024-bit).
poc/poc_file_no_check.py — file transfer checked only at end (no per-chunk verification).



## How to run the PoCs
From repository root:
# run each PoC (they print output demonstrating the vulnerability)
python poc/poc_presence_poison.py
python poc/poc_replay.py
python poc/poc_weak_rsa.py
python poc/poc_file_no_check.py

Each script prints a short demonstration and a Fix. The scripts are self-contained and print human-readable evidence of the vulnerability which are explained below.

## Backdoors, PoC evidence, and what they prove

## 1) Presence poisoning — USER_ADVERTISE accepted without authentication

What the PoC shows
An unauthenticated client sends a USER_ADVERTISE claiming user_id = victim_user.
The server updates its routing table (user_locations) to point victim_user to the attacker host.
Result: messages addressed to victim_user would be routed to the attacker.

Command (example)
python poc/poc_presence_poison.py

Expected output (excerpt)
[setup] initial user_locations: {'victim_user': '10.0.0.5:9000'}
[server] Received USER_ADVERTISE: user_id=victim_user, host=127.0.0.1:9999, conn_auth=None
[server] user_locations updated: {'victim_user': '127.0.0.1:9999'}
[route] Message to victim_user would be routed to 127.0.0.1:9999 (attacker)

Why this matters
-  Exploitable for message interception and impersonation. Presence advertisements are a protocol-level trust boundary; they must be authenticated or bound to a verified session.

Fix
-  Only accept USER_ADVERTISE from a connection authenticated as that user_id.
-  Require a cryptographic signature on USER_ADVERTISE and verify it with the user’s registered public key (include timestamp to prevent replay).



## 2) Missing duplicate-message suppression → replay acceptance

What the PoC shows
A message with a stable msg_id is processed once.
The same encoded message is re-submitted and processed again by the vulnerable handler (duplicate side-effects).
A fixed handler demonstrates dropping the replayed message.

Command
python poc/poc_replay.py

Expected output (excerpt)
[setup] Vulnerable run:
[vuln] Processing message id=b240387c-729e-49a4-9c57-c228b7c8fd06: action=create_item
[exploit] Re-send same frame (vulnerable will process again):
[vuln] Processing message id=b240387c-729e-49a4-9c57-c228b7c8fd06: action=create_item

[fixed run]
[fixed] Processing message id=b240387c-729e-49a4-9c57-c228b7c8fd06: action=create_item
[fixed] Re-send same frame (should be dropped):
[fixed] Dropping replayed message id=b240387c-729e-49a4-9c57-c228b7c8fd06

Why this matters
-  Replaying messages can duplicate effects (files, DB rows, commands), cause logic inconsistencies, or enable DoS.

Fix
-  Add a replay cache that atomically checks-and-adds msg_id before processing (thread-safe).
-  Use bounded expiry for the cache.
-  Log and alert on repeated replay attempts.

## 3) Accepting weak RSA parameters (e.g., RSA-1024)

What the PoC shows
A weak 1024-bit RSA public key is registered by an import path that only parses the key and does not validate its parameters.
A validation function rejects the 1024-bit key but accepts valid 4096-bit keys.

Command
python poc/poc_weak_rsa.py

Expected output (excerpt)
[setup] Generating 1024-bit test key (weak)...
[vuln] Registered key (no param checks).
[vuln] key_size = 1024 bits
[fixed] Attempt to validate (should reject):
[fixed] Validating key parameters...
[fixed] Rejected: Reject: modulus 1024 bits
[setup] Generating 4096-bit strong key...
[fixed] Validating key parameters...
[fixed] key accepted

Why this matters
-  Accepting weak keys undermines authentication and signature security. Attackers could choose easily-breakable parameters.
  
Fix
-  On public-key import, call public_numbers() and enforce n.bit_length() >= 2048 (prefer 3072/4096).
-  Restrict allowed public exponents (e.g., accept only 65537).
-  Prefer modern algorithms (Ed25519) for new keys.

## 4) File transfer integrity only checked at end (no per-chunk verification)

What the PoC shows
Server writes incoming chunks directly to a temp file.
An attacker-corrupted chunk is written during transfer; final integrity check (SHA-256) fails and file is deleted — but the corrupted partial file existed on disk during transfer and could be misused if not correctly sandboxed.
Demonstrates the need for per-chunk checks and atomic commit.

Command
python poctests/poc4_file_no_check.py

Expected output (excerpt)
expected sha for original: 20408ff12442cf3339b869d3c70c42ba0ace9ee79f523170e47958229aa310b1
simulate: corrupted chunk during transfer
[vuln] writing to /tmp/tmp7fbnoc65
[vuln] write chunk 0, size=1024
[vuln] partial size 1024
[vuln] write chunk 1, size=1024
[vuln] partial size 2048
[vuln] final sha: 4f8e7db00bf5d6acf001768978a594c53ac256e4b37fafad55b7664637557cc1
[vuln] mismatch -> deleting temp file
result: False

Why this matters
-  Partial files written during transfer may be read/processed prematurely or can cause disk/IO resource issues. Relying solely on an end-of-transfer hash leaves a window of exposure.

Fix
-  Require a signed manifest (filename, size, final SHA) verified before transfer starts.
-  Verify per-chunk hashes or HMACs as chunks are received.
-  Use an atomic commit pattern: write to sandboxed temp location and only move to final location after full and successful verification.

## Final notes
These PoCs are intentionally and safe — they do not exfiltrate data or contact external hosts. They are designed to be run only in the test harness and to show clear cause/effect for graders.

# Project Milestones

## Milestone 0 — Skeleton & Dev Environment (DONE)
- Create repo, virtualenv/Poetry, CI (GitHub Actions), basic README and run commands.  
- Add config file template (bootstrap_servers, ports, paths).  

## Milestone 1 — In-Memory Server + WS Listener (No Crypto) (DONE)
- Implement basic asyncio WebSocket server that accepts connections and parses JSON envelopes.  
- Distinguish Server vs User connections by the first message type (`SERVER_HELLO_JOIN` / `USER_HELLO` or provided field).  
- Implement in-memory tables (`local_users`, `servers`, `user_locations`).  
- Implement `route_to_user()` using in-memory tables (no crypto yet).  
- Add loop suppression (`seen_ids`).  
- Add minimal unit tests for routing.  

## Milestone 2 — Canonicalisation, Signing Helpers & Key Management (DONE)
- Implement `canonicalize(payload)` and sign/verify wrappers using cryptography.  
- Build key storage helpers (generate RSA-4096, export public as base64url).  
- Implement base64url encoding helpers (no padding).  
- Unit tests: sign + verify roundtrip.  

## Milestone 3 — User HELLO, Advertise/Remove & Gossip (DONE)
- Implement `USER_HELLO` accept/reject logic, set `local_users`, and emit `USER_ADVERTISE` to other servers.  
- Implement `USER_REMOVE` on disconnect logic.  
- Add tests for presence gossip processing (verify signature, update mapping).  

## Milestone 4 — End-to-End Encrypted Messaging (DM) (DONE)
- Implement client-side helper to:  
  - Generate RSA-4096 key.  
  - Use RSA-4096 to encrypt message. 
  - Wrap key with recipient RSA-OAEP(SHA-256).  
  - Sign `content_sig` over `<b64url RSASSA-PSS(SHA-256) over ciphertext|from|to|ts`.  
- Implement server handling of `MSG_DIRECT` to forward as `USER_DELIVER` or `SERVER_DELIVER` (without decrypting).  
- Add unit/integration test verifying server does not decrypt and recipient can verify + decrypt.  

## Milestone 5 — Public Channel & Group Keys (DONE) (BUG FIX NEEDED FOR CONNECTING AND RECONNECTING)
- Implement group key generation (random 256-bit).  
- Per-member RSA-OAEP wrapping.  
- Implement `PUBLIC_CHANNEL_KEY_SHARE`, `PUBLIC_CHANNEL_ADD`, and fan-out of `MSG_PUBLIC_CHANNEL` messages.  
- Ensure servers do not decrypt.  

## Milestone 6 — File Transfer (IN PROGRESS)
- Implement `FILE_START`, chunking with `FILE_CHUNK` frames (encrypt each chunk with same AES key and include `wrapped_key` for DM mode).  
- Validate SHA-256 manifest at the end.  

## Milestone 7 — Bootstrap & Server Linking (IN BRANCH TO BE MERGED)
- Implement introducer flow (static bootstrap list).  
- Implement `SERVER_HELLO_JOIN`, `SERVER_WELCOME`, `SERVER_ANNOUNCE`.  
- Establish persistent authenticated connections to every server in the list.  
- Verify server pubkeys.  

## Milestone 8 — Robustness, Heartbeats, Timeouts
- Add heartbeat sending/receiving (15s/45s).  
- Add reconnection logic using `server_addrs`.  
- Integrate loop suppression and `seen_ids` TTL cleanup.  

## Milestone 9 — Persistence, Directory, and Deployment
- Implement DB schema (`users`, `groups`, `group_members`) via SQLAlchemy + migrations.  
- Implement directory functions (register user pubkey, get_pubkey with directory signature).  

## Milestone 10 — Tests, Compliance & Backdoors
- Write unit tests and async integration tests covering compliance checklist items:  
  - RSA-4096 
  - Content signatures  
  - Transport signatures  
  - Presence  
  - Routing  
  - Heartbeats  
- Implement `backdoor_mode` test cases with at least two allowed vulnerabilities.  
- Document the backdoors.