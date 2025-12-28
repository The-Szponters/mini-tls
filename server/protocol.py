import json
import hashlib
import hmac
import random


# Diffie-Hellman Parameters
P = 2147483647  # 2^31 - 1
G = 16807


def generate_keypair():
    """Generates a private and public key."""
    private_key = random.randint(1, P - 1)
    public_key = pow(G, private_key, P)
    return private_key, public_key


def compute_secret(private_key, other_public_key):
    """Computes the shared secret."""
    return pow(other_public_key, private_key, P)


def derive_keys(shared_secret):
    """Derives encryption and MAC keys from the shared secret."""
    secret_bytes = str(shared_secret).encode()
    # Derive two separate keys for Encryption and MAC
    enc_key = hashlib.sha256(secret_bytes + b"ENC").digest()
    mac_key = hashlib.sha256(secret_bytes + b"MAC").digest()
    return enc_key, mac_key


def xor_cipher(data: bytes, key: bytes) -> bytes:
    """
    Simple stream cipher using the key to seed a PRNG.
    This simulates a One-Time Pad (OTP) stream.
    """
    # Use a local Random instance to be thread-safe
    rng = random.Random(key)
    keystream = bytes([rng.randint(0, 255) for _ in range(len(data))])
    return bytes([a ^ b for a, b in zip(data, keystream)])


def encrypt_then_mac(message: str, enc_key: bytes, mac_key: bytes) -> str:
    """
    Implements Encrypt-then-MAC.
    1. Encrypt the message.
    2. Compute MAC over the ciphertext.
    """
    ciphertext = xor_cipher(message.encode("utf-8"), enc_key)
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).hexdigest()

    return json.dumps({"ciphertext": ciphertext.hex(), "mac": mac})


def verify_mac_then_decrypt(payload: str, enc_key: bytes, mac_key: bytes) -> str:
    """
    Verifies MAC and then decrypts.
    """
    try:
        data = json.loads(payload)
        ciphertext = bytes.fromhex(data["ciphertext"])
        received_mac = data["mac"]
    except (KeyError, ValueError, json.JSONDecodeError):
        raise ValueError("Invalid message format")

    # Verify MAC
    expected_mac = hmac.new(mac_key, ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, received_mac):
        raise ValueError("Integrity check failed! MAC does not match.")

    # Decrypt
    plaintext = xor_cipher(ciphertext, enc_key)
    return plaintext.decode("utf-8")
