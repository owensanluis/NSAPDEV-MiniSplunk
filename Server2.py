import socket
import threading
import re
from collections import defaultdict

# Shared data storage
log_data = []
log_lock = threading.Lock()

# Inverted indexes for fast lookups
index_hostname  = defaultdict(list)   # hostname  -> [LogEntry, ...]
index_daemon    = defaultdict(list)   # daemon    -> [LogEntry, ...]
index_severity  = defaultdict(list)   # severity  -> [LogEntry, ...]
index_timestamp = defaultdict(list)   # "Mon DD"  -> [LogEntry, ...]

# Simple admin credentials
ADMIN_USER = "admin"
ADMIN_PASS = "password123"

client_counter = 0
client_counter_lock = threading.Lock()


# =========================
# Log Entry Representation
# =========================
class LogEntry:
    def __init__(self, timestamp, hostname, daemon, severity, message):
        self.timestamp = timestamp
        self.hostname  = hostname
        self.daemon    = daemon
        self.severity  = severity
        self.message   = message

    def getLog(self):
        return (f"[{self.timestamp}] {self.hostname} {self.daemon} "
                f"({self.severity}): {self.message}")


# =========================
# Parsing Module
# =========================
def parse_syslog(line):
    pattern = r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s+(.*)"
    match = re.match(pattern, line)
    if not match:
        return None

    timestamp, hostname, daemon, message = match.groups()

    msg_lower = message.lower()
    if re.search(r'\b(emerg|emergency)\b', msg_lower):
        severity = "EMERGENCY"
    elif re.search(r'\b(alert)\b', msg_lower):
        severity = "ALERT"
    elif re.search(r'\b(crit|critical)\b', msg_lower):
        severity = "CRITICAL"
    elif re.search(r'\b(err|error)\b', msg_lower):
        severity = "ERROR"
    elif re.search(r'\b(warn|warning)\b', msg_lower):
        severity = "WARNING"
    elif re.search(r'\b(notice)\b', msg_lower):
        severity = "NOTICE"
    elif re.search(r'\b(debug)\b', msg_lower):
        severity = "DEBUG"
    else:
        severity = "INFORMATIONAL"

    return LogEntry(timestamp, hostname, daemon, severity, message)


# =========================
# Index Management
# =========================
def _index_entry(entry):
    """Add a LogEntry to all inverted indexes. Caller must hold log_lock."""
    index_hostname[entry.hostname.lower()].append(entry)
    index_daemon[entry.daemon.lower()].append(entry)
    index_severity[entry.severity.upper()].append(entry)
    # Index by "Mon DD" prefix (first two whitespace-delimited tokens)
    prefix = " ".join(entry.timestamp.split()[:2])
    index_timestamp[prefix].append(entry)


def _clear_indexes():
    """Wipe all indexes. Caller must hold log_lock."""
    index_hostname.clear()
    index_daemon.clear()
    index_severity.clear()
    index_timestamp.clear()


# =========================
# Query Module
# =========================
SEVERITY_MAP = {
    "0": "EMERGENCY",
    "1": "ALERT",
    "2": "CRITICAL",
    "3": "ERROR",
    "4": "WARNING",
    "5": "NOTICE",
    "6": "INFORMATIONAL",
    "7": "DEBUG",
}


def search_by_hostname(value):
    with log_lock:
        entries = list(index_hostname.get(value.lower(), []))
    return [e.getLog() for e in entries]


def search_by_daemon(value):
    with log_lock:
        entries = list(index_daemon.get(value.lower(), []))
    return [e.getLog() for e in entries]


def search_by_severity(value):
    # Accept numeric codes as well as string names
    value = SEVERITY_MAP.get(value, value).upper()
    with log_lock:
        entries = list(index_severity.get(value, []))
    return [e.getLog() for e in entries]


def search_by_timestamp(value):
    """
    Match logs whose timestamp *starts with* the supplied value.
    Fast path: check the "Mon DD" index first; fall back to a filtered
    scan only when the value is more specific (e.g. includes time).
    """
    value = value.strip()
    prefix_key = " ".join(value.split()[:2])   # "Mon DD"

    with log_lock:
        candidates = list(index_timestamp.get(prefix_key, []))

    # If the user supplied a full or partial timestamp beyond "Mon DD",
    # narrow down within the candidates (still much smaller than log_data).
    if len(value.split()) > 2:
        candidates = [e for e in candidates if e.timestamp.startswith(value)]

    return [e.getLog() for e in candidates]


def search_keyword(word):
    # Copy first, then release lock before the string scan
    with log_lock:
        snapshot = list(log_data)
    word_lower = word.lower()
    return [e.getLog() for e in snapshot if word_lower in e.message.lower()]


def count_keyword(word):
    with log_lock:
        snapshot = list(log_data)
    word_lower = word.lower()
    occurrences     = sum(e.message.lower().count(word_lower) for e in snapshot)
    indexed_entries = sum(1 for e in snapshot if word_lower in e.message.lower())
    return occurrences, indexed_entries


# =========================
# Socket helpers
# =========================
def recv_line(conn):
    buffer = b""
    while True:
        chunk = conn.recv(1)
        if not chunk:
            break
        buffer += chunk
        if buffer.endswith(b"\n"):
            break
    return buffer.decode().strip()


def recv_exact(conn, size):
    buffer = b""
    while len(buffer) < size:
        chunk = conn.recv(size - len(buffer))
        if not chunk:
            break
        buffer += chunk
    return buffer


def send_response(conn, message):
    if not message.endswith("\n"):
        message += "\n"
    message += "<<END>>\n"
    conn.send(message.encode())


# =========================
# Client Handler (Thread)
# =========================
def handle_client(conn, addr):
    print(f"[CONNECTED] Client from {addr}")
    is_admin = False

    try:
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break

            parts   = data.strip().split()
            command = parts[0].lower()

            # ---- AUTH ----
            if command == "auth":
                if len(parts) >= 3 and parts[1] == ADMIN_USER and parts[2] == ADMIN_PASS:
                    is_admin = True
                    send_response(conn, "[Server Response] Authentication Successful. Good to see you, Admin!")
                else:
                    send_response(conn, "[Server Response] Authentication Failed.")

            # ---- INGEST ----
            elif command == "ingest":
                with log_lock:
                    send_response(conn, "[Server Response] READY")

                    filesize_line = recv_line(conn)
                    filename_line = recv_line(conn)
                    try:
                        filesize = int(filesize_line)
                    except ValueError:
                        send_response(conn, "[Server Response] ERROR: Invalid filesize")
                        continue

                    raw_bytes = recv_exact(conn, filesize)
                    raw       = raw_bytes.decode(errors='ignore')

                    parsed_count = 0
                    for line in raw.splitlines():
                        entry = parse_syslog(line)
                        if entry:
                            log_data.append(entry)
                            _index_entry(entry)   # build indexes on ingest
                            parsed_count += 1

                send_response(
                    conn,
                    f"[Server Response] Ingest of the file {filename_line} "
                    f"with size {filesize_line} bytes completed. "
                    f"{parsed_count} log entries indexed."
                )
                print(f"[INGESTED] {filename_line} ({filesize} bytes) from {addr} — "
                      f"{parsed_count} entries indexed.", flush=True)

            # ---- SEARCH_DATE ----
            elif command == "search_date":
                query   = " ".join(parts[1:])
                results = search_by_timestamp(query)
                print(f"[NOTICE] {addr} queried date \"{query}\"", flush=True)
                if not results:
                    send_response(conn, f"[Server Response] No logs found for the specified date.")
                else:
                    send_response(conn, f"[Server Response] {len(results)} log(s) found for the date \"{query}\":\n"
                                        + "\n".join(results))

            # ---- SEARCH_HOST ----
            elif command == "search_host":
                results = search_by_hostname(parts[1])
                print(f"[NOTICE] {addr} queried host \"{parts[1]}\"", flush=True)
                if not results:
                    send_response(conn, "[Server Response] No logs found for the specified host.")
                else:
                    send_response(conn, f"[Server Response] {len(results)} log(s) found for the host \"{parts[1]}\":\n"
                                        + "\n".join(results))

            # ---- SEARCH_DAEMON ----
            elif command == "search_daemon":
                results = search_by_daemon(parts[1])
                print(f"[NOTICE] {addr} queried daemon \"{parts[1]}\"", flush=True)
                if not results:
                    send_response(conn, "[Server Response] No logs found for the specified daemon.")
                else:
                    send_response(conn, f"[Server Response] {len(results)} log(s) found for the daemon \"{parts[1]}\":\n"
                                        + "\n".join(results))

            # ---- SEARCH_SEVERITY ----
            elif command == "search_severity":
                results = search_by_severity(parts[1])
                print(f"[NOTICE] {addr} queried severity \"{parts[1]}\"", flush=True)
                if not results:
                    send_response(conn, "[Server Response] No logs found for the specified severity.")
                else:
                    send_response(conn, f"[Server Response] {len(results)} log(s) found for the severity \"{parts[1]}\":\n"
                                        + "\n".join(results))

            # ---- SEARCH_KEYWORD ----
            elif command == "search_keyword":
                results = search_keyword(parts[1])
                print(f"[NOTICE] {addr} queried keyword \"{parts[1]}\"", flush=True)
                if not results:
                    send_response(conn, "[Server Response] No logs found for the specified keyword.")
                else:
                    send_response(conn, f"[Server Response] {len(results)} log(s) found for the keyword \"{parts[1]}\":\n"
                                        + "\n".join(results))

            # ---- COUNT_KEYWORD ----
            elif command == "count_keyword":
                occurrences, indexed_entries = count_keyword(parts[1])
                print(f"[NOTICE] {addr} counted keyword \"{parts[1]}\"", flush=True)
                send_response(conn, f"[Server Response] The keyword \"{parts[1]}\" appeared "
                                    f"{occurrences} time(s) in {indexed_entries} indexed log entrie(s).")

            # ---- COUNT_LOGS ----
            elif command == "count_logs":
                with log_lock:
                    count = len(log_data)
                print(f"[NOTICE] {addr} queried total log count. Current count: {count}", flush=True)
                send_response(conn, f"[Server Response] Total Logs: {count}")

            # ---- LIST_LOGS ----
            elif command == "list_logs":
                with log_lock:
                    snapshot = list(log_data)
                if not snapshot:
                    send_response(conn, "[Server Response] No logs available.")
                    print(f"[NOTICE] {addr} listed logs — none available.", flush=True)
                else:
                    logs = "\n".join(e.getLog() for e in snapshot)
                    print(f"[NOTICE] {addr} listed all {len(snapshot)} logs.", flush=True)
                    send_response(conn, logs)

            # ---- PURGE ----
            elif command == "purge":
                if not is_admin:
                    send_response(conn, "[Server Response] ERROR: Admin Only!")
                    print(f"[NOTICE] {addr} attempted purge without admin privileges.", flush=True)
                else:
                    with log_lock:
                        count = len(log_data)
                        log_data.clear()
                        _clear_indexes()
                    send_response(conn, f"[Server Response] Database purged. {count} log entries removed.")
                    print(f"[ADMIN ACTION] {addr} purged the database — {count} entries removed.", flush=True)

            # ---- EXIT ----
            elif command == "exit":
                send_response(conn, "[Server Response] Goodbye! Thank you for using the San Luis syslog server!")
                print(f"[NOTICE] {addr} disconnected.", flush=True)
                break

            else:
                send_response(conn, "[Server Response] Unknown Command. Please try again.")

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        conn.close()
        print(f"[DISCONNECTED] Client from {addr}")


# =========================
# Main Server
# =========================
def start_server():
    while True:
        bind_host      = input("Host to bind (Recommended [127.0.0.1]): ").strip()
        bind_port_text = input("Port to bind (Recommended [9090]): ").strip()
        try:
            bind_port = int(bind_port_text)
        except ValueError:
            print("Invalid port. Please enter a valid integer for the port.")
            continue

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((bind_host, bind_port))
        server.listen()
        break

    print(f"[SERVER RUNNING] {bind_host}:{bind_port}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    start_server()