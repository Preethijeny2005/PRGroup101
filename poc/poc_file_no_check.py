# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

"""
poc_file_no_check.py

Purpose:
 - Demonstrates the risk of verifying file integrity only AFTER the transfer completes.
 - The PoC shows how corrupted chunks can be written to disk during the transfer window,
   and only detected at the end when the final SHA-256 is computed.

What this PoC demonstrates:
 1. The server writes chunks immediately to a temporary file (no per-chunk validation).
 2. An attacker-corrupted chunk is still written to disk; the file is only detected as corrupted
    once the final SHA-256 is computed and compared to the expected value.
 3. Although the file is deleted on mismatch, the partial corrupted data was present on disk during the transfer,
    which creates an exposure window (other processes might read it, backups might pick it up, etc.).

How to run:
  python poc_file_no_check.py

Expected output:
 - prints the expected SHA256 for the original content
 - prints per-chunk writes and partial file sizes
 - prints final sha that differs from expected, and removal of the temp file
"""

import hashlib, tempfile, os
def sha256(d): return hashlib.sha256(d).hexdigest()

def vulnerable_receive(chunks, expected_sha=None):
    """
    Vulnerable chunk receiver:
    - Writes each incoming chunk to a NamedTemporaryFile immediately (no per-chunk verification).
    - After all chunks are written, computes final SHA-256 and compares to expected_sha.
    - Demonstrates that corruption only discovered at final stage (exposure window exists).
    """
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmpname = tmp.name
    print("[vuln] writing to", tmpname)
    for i, c in enumerate(chunks):
        # Write chunk and flush so partial content is visible on the filesystem
        print(f"[vuln] write chunk {i}, size={len(c)}")
        tmp.write(c); tmp.flush()
        # Show that partial data exists on disk (demonstrates exposure window)
        print("[vuln] partial size", os.path.getsize(tmpname))
    tmp.close()

    # Compute final hash and compare
    with open(tmpname, 'rb') as fh:
        got = fh.read()
    got_sha = sha256(got)
    print("[vuln] final sha:", got_sha)

    if expected_sha and got_sha != expected_sha:
        print("[vuln] mismatch -> deleting temp file")
        os.remove(tmpname)
        return False

    # On success, atomically rename to final path (simplified here)
    final = tmpname + ".final"
    os.rename(tmpname, final)
    print("[vuln] accepted ->", final)
    # clean up for PoC: delete final file
    os.remove(final)
    return True

def simulate():
    """
    Create an 'original' file content and then simulate transfer where the second chunk is corrupted.
    """
    original = b'A' * 1024 + b'B' * 1024
    expected = sha256(original)
    # Simulate an attacker corrupting the second chunk:
    chunks = [original[:1024], b'X' * 1024]  # second chunk corrupted intentionally
    print("expected sha for original:", expected)
    print("simulate: corrupted chunk during transfer")
    res = vulnerable_receive(chunks, expected_sha=expected)
    print("result:", res)

if __name__ == '__main__':
    simulate()
