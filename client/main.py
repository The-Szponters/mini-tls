import socket
import threading
import json
import protocol
import os
import argparse

HOST = os.getenv("SERVER_HOST", "127.0.0.1")
PORT = 8080


def receive_messages(sock, state):
    """
    Thread to receive messages from server.
    state is a dict to share keys and status.
    """
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("[DISCONNECTED] Server closed connection.")
                state["connected"] = False
                state["authenticated"] = False
                break

            message_str = data.decode("utf-8")

            # Check if we are waiting for ServerHello (unencrypted)
            if not state["authenticated"]:
                try:
                    msg = json.loads(message_str)
                    if msg.get("type") == "ServerHello":
                        server_pub = msg.get("public_key")

                        # Compute shared secret
                        secret = protocol.compute_secret(
                            state["private_key"], server_pub
                        )
                        enc_key, mac_key = protocol.derive_keys(secret)

                        state["enc_key"] = enc_key
                        state["mac_key"] = mac_key
                        state["authenticated"] = True

                        # Log keys for Wireshark analysis
                        try:
                            with open("client_secrets.log", "a") as f:
                                f.write(
                                    f"Session with Server | "
                                    f"ENC_KEY={enc_key.hex()} | "
                                    f"MAC_KEY={mac_key.hex()}\n"
                                )
                        except Exception as e:
                            print(f"[WARNING] Could not write secrets: {e}")

                        print("[HANDSHAKE] Secure connection established.")
                    else:
                        print(f"[ERROR] Expected ServerHello, got {msg}")
                except json.JSONDecodeError:
                    print("[ERROR] Invalid JSON from server")
            else:
                # Authenticated: Expect encrypted messages
                try:
                    plaintext = protocol.verify_mac_then_decrypt(
                        message_str, state["enc_key"], state["mac_key"]
                    )
                    msg = json.loads(plaintext)

                    if msg.get("type") == "EndSession":
                        print("[SESSION] Server ended session.")
                        state["authenticated"] = False
                        state["enc_key"] = None
                        state["mac_key"] = None
                        # Do not re-handshake automatically as per user request
                    else:
                        print(f"[SERVER] {msg}")

                except Exception as e:
                    print(f"[ERROR] Decryption failed: {e}")

    except ConnectionResetError:
        print("[DISCONNECTED] Connection reset.")
    except OSError:
        pass  # Socket closed


def start_client():
    parser = argparse.ArgumentParser(description="Mini-TLS Client")
    parser.add_argument("--host", type=str, default=HOST, help="Server host")
    parser.add_argument("-p", "--port", type=int, default=PORT, help="Server port")
    args = parser.parse_args()

    host = args.host
    port = args.port

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    state = {
        "authenticated": False,
        "connected": False,
        "private_key": None,
        "enc_key": None,
        "mac_key": None,
    }

    print(f"Target Server: {host}:{port}")
    print("Commands: connect, send <msg>, end, quit")

    while True:
        try:
            cmd = input("> ")
        except EOFError:
            break

        if cmd == "connect":
            if state["connected"]:
                print("Already connected.")
                continue

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                state["connected"] = True

                # Start receiver thread
                recv_thread = threading.Thread(
                    target=receive_messages, args=(sock, state), daemon=True
                )
                recv_thread.start()

                # Initiate Handshake
                priv, pub = protocol.generate_keypair()
                state["private_key"] = priv

                client_hello = json.dumps({"type": "ClientHello", "public_key": pub})
                sock.sendall(client_hello.encode("utf-8"))
                print("[HANDSHAKE] ClientHello sent.")

            except Exception as e:
                print(f"Connection failed: {e}")
                state["connected"] = False

        elif cmd.startswith("send "):
            if not state["connected"] or not state["authenticated"]:
                print("Not connected or handshake not complete.")
                continue

            text = cmd[5:]
            msg_payload = json.dumps({"type": "Message", "content": text})

            try:
                encrypted_msg = protocol.encrypt_then_mac(
                    msg_payload, state["enc_key"], state["mac_key"]
                )
                sock.sendall(encrypted_msg.encode("utf-8"))
            except OSError:
                print("[ERROR] Failed to send message. Connection lost.")
                state["connected"] = False
                state["authenticated"] = False

        elif cmd == "end":
            if not state["connected"] or not state["authenticated"]:
                print("Not connected.")
                continue

            # Send EndSession
            try:
                end_payload = json.dumps({"type": "EndSession"})
                encrypted_msg = protocol.encrypt_then_mac(
                    end_payload, state["enc_key"], state["mac_key"]
                )
                sock.sendall(encrypted_msg.encode("utf-8"))

                print("[SESSION] Session ended. Closing connection...")

                # Close connection immediately
                sock.close()
                state["connected"] = False
                state["authenticated"] = False
                state["enc_key"] = None
                state["mac_key"] = None

            except OSError:
                print("[ERROR] Connection lost.")
                state["connected"] = False
                state["authenticated"] = False

        elif cmd == "quit":
            if state["connected"]:
                sock.close()
            break
        else:
            print("Unknown command.")


if __name__ == "__main__":
    start_client()
