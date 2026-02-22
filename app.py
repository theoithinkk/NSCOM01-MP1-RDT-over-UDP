import os
import socket
from typing import Tuple

from protocol import MsgType, Packet, build_error
from rdt import RDTError, client_handshake, recv_file, recv_packet, send_file, send_packet, server_handshake


def parse_req(payload: bytes) -> Tuple[str, str]:
    txt = payload.decode("utf-8", errors="replace").strip()
    parts = txt.split(maxsplit=1)
    if len(parts) != 2:
        raise ValueError("Invalid request")
    op, filename = parts
    return op.upper(), filename


def prompt_text(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def prompt_int(label: str, default: int, min_value: int = 1, max_value: int = 65535) -> int:
    while True:
        raw = input(f"{label} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
            if min_value <= value <= max_value:
                return value
            print(f"Enter a value from {min_value} to {max_value}.")
        except ValueError:
            print("Enter a valid integer.")


def prompt_mode() -> str:
    while True:
        mode = input("Select mode: [1] server, [2] client: ").strip().lower()
        if mode in ("1", "server", "s"):
            return "server"
        if mode in ("2", "client", "c"):
            return "client"
        print("Invalid choice. Type 1 for server or 2 for client.")


def prompt_client_op() -> str:
    while True:
        op = input("Operation: [1] get, [2] put: ").strip().lower()
        if op in ("1", "get", "g"):
            return "get"
        if op in ("2", "put", "p"):
            return "put"
        print("Invalid operation. Type 1 for get or 2 for put.")


def run_server() -> None:
    host = prompt_text("Server host", "0.0.0.0")
    port = prompt_int("Server port", 9000, 1, 65535)
    storage = prompt_text("Storage directory", "server_storage")

    os.makedirs(storage, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[server] listening on {host}:{port}")

    while True:
        try:
            session, client_addr = server_handshake(sock)
            print(f"[server] session={session.session_id} peer={client_addr}")
            req_pkt, req_addr = recv_packet(sock, timeout=5.0)
            if req_addr != client_addr:
                continue
            if req_pkt.session_id != session.session_id or req_pkt.msg_type != MsgType.REQ:
                send_packet(sock, client_addr, build_error(session.session_id, 0, "Session mismatch"))
                continue

            op, filename = parse_req(req_pkt.payload)
            safe_name = os.path.basename(filename)
            path = os.path.join(storage, safe_name)

            if op == "GET":
                if not os.path.exists(path):
                    send_packet(sock, client_addr, build_error(session.session_id, 0, "File not found"))
                    continue
                sent = send_file(sock, client_addr, session, path)
                print(f"[server] sent {sent} bytes -> {safe_name}")
            elif op == "PUT":
                received = recv_file(sock, client_addr, session, path)
                print(f"[server] received {received} bytes <- {safe_name}")
            else:
                send_packet(sock, client_addr, build_error(session.session_id, 0, "Unknown operation"))
        except TimeoutError:
            print("[server] timeout; session dropped")
        except RDTError as exc:
            print(f"[server] protocol error: {exc}")
        except Exception as exc:
            print(f"[server] error: {exc}")


def run_client() -> None:
    server_host = prompt_text("Server host", "127.0.0.1")
    server_port = prompt_int("Server port", 9000, 1, 65535)
    op = prompt_client_op()
    remote_file = input("Remote filename: ").strip()
    local_file = input("Local file path: ").strip()
    chunk_size = prompt_int("Chunk size", 1024, 128, 1024)

    if not remote_file:
        raise ValueError("Remote filename is required")
    if not local_file:
        raise ValueError("Local file path is required")

    server_addr = (server_host, server_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    try:
        session = client_handshake(sock, server_addr, chunk_size)
        req = Packet(
            msg_type=MsgType.REQ,
            session_id=session.session_id,
            seq=session.local_seq,
            ack=0,
            payload=f"{op.upper()} {remote_file}".encode("utf-8"),
        )
        send_packet(sock, server_addr, req)

        if op == "get":
            received = recv_file(sock, server_addr, session, local_file)
            print(f"[client] downloaded {received} bytes -> {local_file}")
        else:
            if not os.path.exists(local_file):
                raise FileNotFoundError(local_file)
            sent = send_file(sock, server_addr, session, local_file)
            print(f"[client] uploaded {sent} bytes <- {local_file}")
    finally:
        sock.close()


def main() -> None:
    print("Reliable UDP File Transfer")
    mode = prompt_mode()
    if mode == "server":
        run_server()
    else:
        run_client()


if __name__ == "__main__":
    main()
