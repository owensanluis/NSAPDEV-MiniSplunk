import os
import socket
import shlex
import getpass


def recv_response(sock):
    """Receive response with timeout and progress indication for large responses."""
    sock.settimeout(600) 
    buffer = b""
    total_bytes = 0
    
    try:
        while b"<<END>>\n" not in buffer:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buffer += chunk
            total_bytes += len(chunk)
            
            # Show progress for large responses
            if total_bytes > 100000:  # 100KB
                print(f"[System Message] Receiving response... ({total_bytes//1024}KB)", end='\r', flush=True)
        
        if total_bytes > 100000:
            print(f"[System Message] Response received ({total_bytes//1024}KB)")
            
    except socket.timeout:
        print("[System Message] Response timeout - server may be slow or unresponsive")
        return ""
    finally:
        sock.settimeout(None) 
    
    text = buffer.decode(errors='ignore')
    return text.replace("<<END>>\n", "")


def parse_address(addr_str):
    if ":" not in addr_str:
        raise ValueError("Address must be in <host>:<port> format.")
    host, port_str = addr_str.rsplit(":", 1)
    if not port_str.isdigit():
        raise ValueError("Port must be a valid integer.")
    return host, int(port_str)


def open_connection(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    return client


def main():
    print("[System Message] Syslog Client. Type HELP for available commands.")

    while True:
        try:
            cmd = input("Client >> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[System Message] Client terminated.")
            break

        if not cmd:
            continue

        try:
            tokens = shlex.split(cmd)
        except ValueError as e:
            print(f"[System Message] Parse error: {e}")
            continue

        command = tokens[0].upper()

        # -------------------------
        # HELP
        # -------------------------
        if command == "HELP":
            print(
                "\n[System Message] Available Commands:\n"
                "  INGEST <filepath> <addr>:<port>\n"
                "      Upload a local syslog file to the server for parsing.\n\n"
                "  QUERY <addr>:<port> <SEARCH_CMD> [args...]\n"
                "      Send a search query to the server. SEARCH_CMD can be:\n"
                "        SEARCH_DATE <date>        - Filter logs by date/timestamp prefix\n"
                "        SEARCH_HOST <hostname>    - Filter logs by hostname\n"
                "        SEARCH_DAEMON <daemon>    - Filter logs by daemon/process\n"
                "        SEARCH_SEVERITY <level>   - Filter logs by severity level\n"
                "        SEARCH_KEYWORD <keyword>  - Search logs by keyword\n"
                "        COUNT_KEYWORD <keyword>   - Count occurrences of a keyword\n"
                "        COUNT_LOGS                - Get total number of indexed logs\n"
                "        LIST_LOGS                 - List all indexed logs\n\n"
                "  PURGE <addr>:<port>\n"
                "      Erase all indexed logs (admin credentials required).\n\n"
                "  EXIT\n"
                "      Exit the client.\n"
            )
            continue

        # -------------------------
        # EXIT
        # -------------------------
        if command == "EXIT":
            print("[System Message] Client terminated.")
            break

        # -------------------------
        # INGEST <filepath> <addr>:<port>
        # -------------------------
        elif command == "INGEST":
            if len(tokens) != 3:
                print("[System Message] Usage: INGEST <filepath> <addr>:<port>")
                continue

            filepath, addr_str = tokens[1], tokens[2]

            if not os.path.exists(filepath) or not os.path.isfile(filepath):
                print("[System Message] File does not exist or is not a file.")
                continue

            try:
                host, port = parse_address(addr_str)
            except ValueError as e:
                print(f"[System Message] Invalid address: {e}")
                continue

            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)

            try:
                print(f"[System Message] Connecting to {addr_str}...")
                client = open_connection(host, port)
            except Exception as e:
                print(f"[System Message] Connection failed: {e}")
                continue

            print(f"[System Message] Uploading {filename} ({filesize} bytes)...")

            client.send(f"INGEST {filepath}".encode())
            print(recv_response(client))  # READY

            client.send(f"{filesize}\n".encode())
            client.send(f"{filename}\n".encode())

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    client.send(chunk)

            print(recv_response(client))  # completion message
            client.close()

        # -------------------------
        # QUERY <addr>:<port> <SEARCH_CMD> [args...]
        # -------------------------
        elif command == "QUERY":
            if len(tokens) < 3:
                print("[System Message] Usage: QUERY <addr>:<port> <SEARCH_CMD> [args...]")
                continue

            addr_str = tokens[1]
            sub_command = " ".join(tokens[2:])

            try:
                host, port = parse_address(addr_str)
            except ValueError as e:
                print(f"[System Message] Invalid address: {e}")
                continue

            try:
                print(f"[System Message] Sending query to {addr_str}...")
                client = open_connection(host, port)
            except Exception as e:
                print(f"[System Message] Connection failed: {e}")
                continue

            client.send(sub_command.encode())
            print(recv_response(client))
            client.close()

        # -------------------------
        # PURGE <addr>:<port>
        # -------------------------
        elif command == "PURGE":
            if len(tokens) != 2:
                print("[System Message] Usage: PURGE <addr>:<port>")
                continue

            addr_str = tokens[1]

            try:
                host, port = parse_address(addr_str)
            except ValueError as e:
                print(f"[System Message] Invalid address: {e}")
                continue

            # Credentials must be sent in the same connection since auth
            # state is per-session on the server.
            print("[System Message] Admin credentials required to purge.")
            user = input("  Username: ").strip()
            password = getpass.getpass("  Password: ")

            try:
                print(f"[System Message] Connecting to {addr_str} to purge records...")
                client = open_connection(host, port)
            except Exception as e:
                print(f"[System Message] Connection failed: {e}")
                continue

            client.send(f"AUTH {user} {password}".encode())
            auth_response = recv_response(client)
            print(auth_response)

            if "Successful" in auth_response:
                client.send(b"PURGE")
                print(recv_response(client))

            client.close()

        else:
            print("[System Message] Unknown command. Type HELP for a list of commands.")


if __name__ == "__main__":
    main()