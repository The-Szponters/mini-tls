import socket
import threading
import json
import protocol
import argparse

HOST = "0.0.0.0"
PORT = 8080

clients = {}
active_connections = 0
clients_lock = threading.Lock()
active_connections_lock = threading.Lock()


def handle_client(conn, addr):
    global active_connections
    print(f"[NEW CONNECTION] {addr} connected.")

    # Initial state
    enc_key = None
    mac_key = None
    authenticated = False

    try:
        while True:
            # Read data
            data = conn.recv(4096)
            if not data:
                break

            message_str = data.decode("utf-8")

            # If not authenticated, we expect ClientHello (JSON)
            if not authenticated:
                try:
                    msg = json.loads(message_str)
                    if msg.get("type") == "ClientHello":
                        client_pub = msg.get("public_key")
                        p = msg.get("p")
                        g = msg.get("g")

                        if not all([client_pub, p, g]):
                            print(
                                f"[ERROR] Invalid ClientHello from {addr}: missing p or g"
                            )
                            break

                        # Generate Server keys using client's DH parameters
                        priv, pub = protocol.generate_keypair(p, g)

                        # Compute shared secret
                        secret = protocol.compute_secret(priv, client_pub, p)
                        enc_key, mac_key = protocol.derive_keys(secret)

                        # Log keys for Wireshark analysis
                        try:
                            with open("/captures/server_secrets.log", "a") as f:
                                f.write(
                                    f"Client {addr} | P={p} | G={g} | "
                                    f"ENC_KEY={enc_key.hex()} | "
                                    f"MAC_KEY={mac_key.hex()}\n"
                                )
                        except Exception as e:
                            print(f"[WARNING] Could not write secrets: {e}")

                        # Send ServerHello
                        response = json.dumps(
                            {"type": "ServerHello", "public_key": pub}
                        )
                        conn.sendall(response.encode("utf-8"))

                        authenticated = True
                        with clients_lock:
                            clients[addr] = {
                                "conn": conn,
                                "enc_key": enc_key,
                                "mac_key": mac_key,
                            }
                        print(f"[HANDSHAKE] Keys exchanged with {addr} (P={p}, G={g})")
                    else:
                        print(
                            f"[ERROR] Expected ClientHello from {addr}, " f"got {msg}"
                        )
                        break
                except json.JSONDecodeError:
                    print(f"[ERROR] Invalid JSON from {addr}")
                    break
            else:
                # Authenticated state: Expect encrypted messages
                try:
                    # Decrypt and verify
                    plaintext = protocol.verify_mac_then_decrypt(
                        message_str, enc_key, mac_key
                    )
                    msg = json.loads(plaintext)

                    if msg.get("type") == "EndSession":
                        print(f"[SESSION END] Client {addr} ended session.")
                        with clients_lock:
                            del clients[addr]
                            return

                    elif msg.get("type") == "Message":
                        print(f"[MSG] {addr}: {msg.get('content')}")

                    else:
                        print(f"[UNKNOWN] Encrypted message from {addr}: {msg}")

                except Exception as e:
                    print(f"[ERROR] Decryption/Verification failed for {addr}: " f"{e}")

    except ConnectionResetError:
        pass
    finally:
        print(f"[DISCONNECT] {addr} disconnected.")
        with clients_lock:
            if addr in clients:
                del clients[addr]
            global active_connections
            active_connections -= 1
        conn.close()


def server_cli():
    while True:
        try:
            cmd = input()
        except EOFError:
            break

        if cmd.startswith("list"):
            with clients_lock:
                print(f"Connected clients: {list(clients.keys())}")
        elif cmd.startswith("kill"):
            # Format: kill <ip> <port>
            parts = cmd.split()
            if len(parts) == 3:
                target_ip = parts[1]
                target_port = int(parts[2])
                target_addr = (target_ip, target_port)

                with clients_lock:
                    if target_addr in clients:
                        client_data = clients[target_addr]
                        conn = client_data["conn"]
                        enc_key = client_data["enc_key"]
                        mac_key = client_data["mac_key"]

                        try:
                            # Send EndSession
                            end_msg = json.dumps({"type": "EndSession"})
                            encrypted = protocol.encrypt_then_mac(
                                end_msg, enc_key, mac_key
                            )
                            conn.sendall(encrypted.encode("utf-8"))

                            conn.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass

                        del clients[target_addr]
                        print(f"Killed connection to {target_addr}")
                    else:
                        print("Client not found.")
            else:
                print("Usage: kill <ip> <port>")
        elif cmd == "help":
            print("Commands: list, kill <ip> <port>")


def start_server():
    global active_connections
    parser = argparse.ArgumentParser(description="Mini-TLS Server")
    parser.add_argument(
        "-p", "--port", type=int, default=PORT, help="Port to listen on"
    )
    parser.add_argument(
        "-n",
        "--max-clients",
        type=int,
        default=3,
        help="Max number of clients",
    )
    args = parser.parse_args()
    port = args.port
    max_clients = args.max_clients

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, port))
    server.listen()
    print(f"[START] Server listening on {HOST}:{port} " f"(Max clients: {max_clients})")

    # Start CLI thread
    cli_thread = threading.Thread(target=server_cli, daemon=True)
    cli_thread.start()

    while True:
        conn, addr = server.accept()

        with clients_lock:
            if active_connections >= max_clients:
                print(f"[REJECT] {addr} rejected (Server full)")
                conn.close()
                continue
            active_connections += 1
        print(active_connections)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    start_server()
