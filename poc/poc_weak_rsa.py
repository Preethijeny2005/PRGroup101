# team members Luke Stassinopoulos, John Watson, Cameron Gilbert, Bailey Nathan, Rhett Calnan
# Group 101

"""
poc_weak_rsa.py

Purpose:
 - Demonstrates a weak-key acceptance issue: the vulnerable registration accepts any parseable
   public key without validating cryptographic parameters (modulus size, exponent).
 - The fixed registration validates key parameters and rejects weak keys.

Why it matters:
 - Accepting small RSA moduli (e.g. 1024 bits) or unusual exponents makes signatures and encryption
   dramatically weaker and easier to break. Systems should validate public-key parameters on import.

How to run:
  python poc_weak_rsa.py

Expected behavior:
 - If 'cryptography' is available: generate a 1024-bit key, vulnerable path accepts it (shows key_size),
   fixed validation rejects it, and a 4096-bit key is accepted by the fixed validation.
"""

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    crypto = True
except Exception:
    crypto = False

def vulnerable_register(key_obj):
    """
    Vulnerable key registration:
    - Accepts the key object without checking modulus size or exponent.
    - In a real application the key would be stored and used for verification/encryption.
    """
    print("[vuln] Registered key (no param checks).")
    if hasattr(key_obj, 'key_size'):
        print(f"[vuln] key_size = {key_obj.key_size} bits")
    else:
        print("[vuln] simulated key object accepted")

def validate_and_register(key_obj):
    """
    Fixed registration:
    - Verifies key parameters (modulus bit-length >= 2048).
    - Optionally check exponent (e.g. ensure e == 65537).
    - Rejects keys that do not meet the criteria.
    """
    print("[fixed] Validating key parameters...")
    if hasattr(key_obj, 'key_size'):
        nbits = key_obj.key_size
        if nbits < 2048:
            raise ValueError(f"Reject: modulus {nbits} bits")
        # Optionally: check exponent with key_obj.public_numbers().e
        print("[fixed] key accepted")
    elif isinstance(key_obj, dict):
        nbits = key_obj.get('n_bits', 0)
        if nbits < 2048:
            raise ValueError("Reject simulated small key")
        print("[fixed] simulated key accepted")
    else:
        raise ValueError("Unknown key")

def simulate():
    """
    If cryptography is available, generate test keys; otherwise, use simulated dict objects.
    Demonstrates vulnerable acceptance vs fixed rejection.
    """
    if crypto:
        print("[setup] Generating 1024-bit test key (weak)...")
        priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pub = priv.public_key()

        print("[vuln test] Vulnerable registration (should accept weak):")
        vulnerable_register(pub)

        print("\n[fixed test] Validation should reject this key:")
        try:
            validate_and_register(pub)
        except Exception as e:
            print("[fixed] Rejected:", e)

        print("\n[setup] Generating 4096-bit strong key...")
        priv2 = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        pub2 = priv2.public_key()
        print("[fixed test] Strong key registration (should be accepted):")
        validate_and_register(pub2)
    else:
        print("[note] cryptography unavailable — using simulated keys")
        vulnerable_register({'n_bits': 1024})
        try:
            validate_and_register({'n_bits': 1024})
        except Exception as e:
            print("[fixed] Rejected:", e)
        validate_and_register({'n_bits': 4096})

if __name__ == '__main__':
    simulate()
