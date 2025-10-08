# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

import os
import base64
import uuid
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

RSA_KEY_SIZE = 4096

# RSA Key generation
def generate_rsa4096() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    return priv, priv.public_key()

def export_public_base64url(pubkey: RSAPublicKey) -> str:
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64url_encode_no_padding(der)

def import_public_base64url(b64u: str) -> RSAPublicKey:
    der = b64url_decode_no_padding(b64u)
    pub = serialization.load_der_public_key(der)
    if not isinstance(pub, RSAPublicKey):
        raise TypeError("Provided key is not an RSA public key")
    return pub

def save_private_key_pem(privkey: RSAPrivateKey, path: str, password: bytes | None = None):
    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()
    pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    with open(path, "wb") as f:
        f.write(pem)

def load_private_key_pem(path: str, password: bytes | None = None) -> RSAPrivateKey:
    with open(path, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=password)
    if not isinstance(priv, RSAPrivateKey):
        raise TypeError("Provided key is not an RSA private key")
    return priv

# Signing
def sign_bytes(privkey: RSAPrivateKey, data: bytes) -> bytes:
    return privkey.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

# Verification
def verify_bytes(pubkey: RSAPublicKey, data: bytes, signature: bytes) -> bool:
    try:
        pubkey.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# AES-GCM 
def aes_encrypt_gcm(plaintext: bytes, key: bytes | None = None, associated_data: bytes = b"") -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns (ciphertext, iv, tag, key)
    """
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)  # 96-bit IV
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(iv, plaintext, associated_data)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, iv, tag, key

def aes_decrypt_gcm(ciphertext: bytes, iv: bytes, tag: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt AES-256-GCM ciphertext with given IV, tag, and key.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + tag, associated_data)

# AES key wrap
def rsa_wrap_aes_key(pubkey: RSAPublicKey, aes_key: bytes) -> bytes:
    return pubkey.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# RSA-OAEP-SHA256 unwrap 
def rsa_unwrap_aes_key(privkey: RSAPrivateKey, wrapped_key: bytes) -> bytes:
    return privkey.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Base64
def b64url_encode_no_padding(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode("ascii")

def b64url_decode_no_padding(s: str) -> bytes:
    padding = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)
