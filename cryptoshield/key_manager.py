"""
key_manager.py
Password-based key derivation for CryptoShield.

Flow:
    User password
        -> + random salt (new for every encryption)
        -> PBKDF2-HMAC-SHA256 (slow on purpose, makes password guessing expensive)
        -> 32 bytes of key material
        -> HKDF-SHA256 with two different labels
        -> Encryption key (ChaCha20-Poly1305) + Authentication key (HMAC-SHA256)

- The password is never used directly as a key and is never stored.
- The salt is NOT secret. It is stored next to the encrypted data because
  the same salt is needed to rebuild the same keys at decryption time.
- Separate keys for separate purposes is a cryptography best practice
  (never reuse one key for two different algorithms).
- The derived keys only live in memory during a single request.
"""

import os
import hashlib
import unicodedata
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

KEY_LEN = 32               # 256-bit keys for ChaCha20-Poly1305 and HMAC-SHA256
SALT_LEN = 16              # 128-bit random salt
PBKDF2_ITERATIONS = 600_000  # OWASP guidance for PBKDF2-HMAC-SHA256


def generate_salt() -> bytes:
    """Return a fresh random salt."""
    return os.urandom(SALT_LEN)


def password_to_key_material(password: str, salt: bytes) -> bytes:
    """Stretch a password + salt into 32 bytes of key material with PBKDF2-HMAC-SHA256."""
    # NFKC normalisation makes the same visible password work the same everywhere.
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", pw, salt, PBKDF2_ITERATIONS, dklen=KEY_LEN)


def derive_key(key_material: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """
    Derive a sub-key using HKDF (HMAC-SHA256 based).
    'info' is a context label so keys for different purposes
    (b'encryption' vs b'authentication') are cryptographically independent.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(key_material)


def derive_keys_from_password(password: str, salt: bytes):
    """Return (encryption_key, auth_key) derived from the password and salt."""
    key_material = password_to_key_material(password, salt)
    enc_key = derive_key(key_material, b"cryptoshield-encryption-key")
    auth_key = derive_key(key_material, b"cryptoshield-auth-key")
    return enc_key, auth_key


if __name__ == "__main__":
    salt = generate_salt()
    enc_key, auth_key = derive_keys_from_password("example-password", salt)
    again_enc, again_auth = derive_keys_from_password("example-password", salt)
    other_enc, _ = derive_keys_from_password("wrong-password", salt)
    print("Same password + salt -> same keys:", (enc_key, auth_key) == (again_enc, again_auth))
    print("Wrong password -> different key:", enc_key != other_enc)
    print("Encryption and auth keys differ:", enc_key != auth_key)
