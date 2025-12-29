import hashlib
import hmac
import random
import json
import os
import re
import argparse


def load_ciphered_message(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, "r") as f:
        data = json.load(f)
    return data["ciphertext"], data["mac"]


def load_secrets(filepath):
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, "r") as f:
        lines = f.readlines()
    if not lines:
        raise ValueError("Secrets file is empty")

    last_line = lines[-1].strip()
    enc_match = re.search(r"ENC_KEY=([a-fA-F0-9]+)", last_line)
    mac_match = re.search(r"MAC_KEY=([a-fA-F0-9]+)", last_line)

    if not enc_match or not mac_match:
        raise ValueError(f"Failed to parse keys from: {last_line}")
    return enc_match.group(1), mac_match.group(1)


def verify_mac(mac_key: bytes, ciphertext: bytes, received_mac: str) -> bool:
    expected_mac = hmac.new(mac_key, ciphertext, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_mac, received_mac)


def xor_decrypt(data: bytes, key: bytes) -> str:
    rng = random.Random(key)
    keystream = bytes([rng.randint(0, 255) for _ in range(len(data))])
    plaintext_bytes = bytes([a ^ b for a, b in zip(data, keystream)])
    return plaintext_bytes.decode("utf-8")


def run_verification(message_file, secrets_file):
    print("=== Mini-TLS Message Verification ===\n")

    print(f"[INPUT] Message file: {message_file}")
    print(f"[INPUT] Secrets file: {secrets_file}\n")

    try:
        ciphertext_hex, mac_hex = load_ciphered_message(message_file)
        enc_key_hex, mac_key_hex = load_secrets(secrets_file)
    except (FileNotFoundError, ValueError) as e:
        print(f"[ERROR] {e}")
        return False

    ciphertext = bytes.fromhex(ciphertext_hex)
    enc_key = bytes.fromhex(enc_key_hex)
    mac_key = bytes.fromhex(mac_key_hex)

    print(f"[DATA] Ciphertext: {ciphertext_hex[:48]}...")
    print(f"[DATA] MAC: {mac_hex}")
    print(f"[DATA] ENC_KEY: {enc_key_hex[:32]}...")
    print(f"[DATA] MAC_KEY: {mac_key_hex[:32]}...\n")

    print("[1/3] Verifying MAC integrity...")
    if verify_mac(mac_key, ciphertext, mac_hex):
        print("      PASS - MAC valid, message authentic\n")
    else:
        print("      FAIL - MAC mismatch\n")
        return False

    print("[2/3] Tampering simulation...")
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0xFF
    if not verify_mac(mac_key, tampered, mac_hex):
        print("      PASS - Modified message rejected\n")
    else:
        print("      FAIL - Tampering not detected\n")
        return False

    print("[3/3] Decrypting message...")
    try:
        plaintext = xor_decrypt(ciphertext, enc_key)
        print(f"      PASS - Decryption successful")
        print(f"      Plaintext: {plaintext}")
    except Exception as e:
        print(f"      FAIL - {e}\n")
        return False

    print("=== Verification Complete ===")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mini-TLS message verification tool")
    parser.add_argument(
        "message_file", help="Path to JSON file with ciphertext and MAC"
    )
    parser.add_argument(
        "secrets_file", help="Path to secrets log file with ENC_KEY and MAC_KEY"
    )
    args = parser.parse_args()

    run_verification(args.message_file, args.secrets_file)
