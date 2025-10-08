# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import pytest
from socp.crypto import (
    generate_rsa4096,
    export_public_base64url,
    import_public_base64url,
    sign_bytes,
    verify_bytes
)
from socp.utils import json_canonicalize

def test_sign_verify_roundtrip():
    # Generate a new RSA key pair
    priv, pub = generate_rsa4096()

    # Canonicalize JSON data for signing
    data_obj = {"message": "hello", "n": 1}
    canonical = json_canonicalize(data_obj).encode("utf-8")

    # Sign the data
    sig = sign_bytes(priv, canonical)
    assert isinstance(sig, bytes)
    assert len(sig) > 0  # signature should not be empty

    # Verify the signature
    ok = verify_bytes(pub, canonical, sig)
    assert ok is True

def test_public_export_import_roundtrip():
    priv, pub = generate_rsa4096()

    # Export public key to base64url
    exported = export_public_base64url(pub)
    assert isinstance(exported, str)
    assert len(exported) > 0  # sanity check

    # Import the public key back and ensure it matches the original
    imported_pub = import_public_base64url(exported)
    assert imported_pub.public_numbers() == pub.public_numbers()

def test_sign_verify_with_imported_key():
    priv, pub = generate_rsa4096()
    exported = export_public_base64url(pub)
    imported_pub = import_public_base64url(exported)

    # Sign and verify using imported public key
    message = b"test message"
    sig = sign_bytes(priv, message)
    assert verify_bytes(imported_pub, message, sig)
