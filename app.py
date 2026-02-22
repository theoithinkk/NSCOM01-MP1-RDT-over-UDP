import argparse
import os
import socket
from typing import Tuple

from protocol import MsgType, Packet
from rdt import (
    RDTError,
    client_handshake,
    configure_security,
    protect_payload,
    recv_file,
    recv_packet,
    send_file,
    send_packet,
    server_handshake,
    set_wire_trace,
    unprotect_payload,
)


QUIT_WORDS = {"q", "quit", "exit"}


def parse_req(payload: bytes) -> Tuple[str, str]:
    txt = payload.decode("utf-8", errors="replace").strip()
    parts = txt.split(maxsplit=1)
    if len(parts) != 2:
        raise ValueError("Invalid request")
    op, filename = parts
    return op.upper(), filename


def prompt_text(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    if value.lower() in QUIT_WORDS:
        raise KeyboardInterrupt
    return value or default


def prompt_int(label: str, default: int, min_value: int = 1, max_value: int = 65535) -> int:
    while True:
        raw = input(f"{label} [{default}]: ").strip()
        if raw.lower() in QUIT_WORDS:
            raise KeyboardInterrupt
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
        if mode in QUIT_WORDS:
            raise KeyboardInterrupt
        if mode in ("1", "server", "s"):
            return "server"
        if mode in ("2", "client", "c"):
            return "client"
        print("Invalid choice. Type 1 for server or 2 for client.")


def prompt_client_op() -> str:
    while True:
        op = input("Operation: [1] get, [2] put: ").strip().lower()
        if op in QUIT_WORDS:
            raise KeyboardInterrupt
        if op in ("1", "get", "g"):
            return "get"
        if op in ("2", "put", "p"):
            return "put"
        print("Invalid operation. Type 1 for get or 2 for put.")


def run_server(verbose: bool = False) -> None:
    host = prompt_text("Server host", "0.0.0.0")
    port = prompt_int("Server port", 9000, 1, 65535)
    storage = prompt_text("Storage directory", "server_storage")

    os.makedirs(storage, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"[server] listening on {host}:{port}")
    try:
        while True:
            try:
                session, client_addr = server_handshake(sock, verbose=verbose)
                print(f"[server] session={session.session_id} peer={client_addr}")
                req_pkt, req_addr = recv_packet(sock, timeout=5.0)
                if req_addr != client_addr:
                    continue
                if req_pkt.session_id != session.session_id or req_pkt.msg_type != MsgType.REQ:
                    err_payload = protect_payload(
                        session,
                        MsgType.ERROR,
                        session.local_seq,
                        0,
                        b"Session mismatch",
                        outbound=True,
                    )
                    send_packet(sock, client_addr, Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload))
                    continue

                req_plain = unprotect_payload(
                    session,
                    MsgType.REQ,
                    req_pkt.seq,
                    req_pkt.ack,
                    req_pkt.payload,
                    outbound=False,
                )
                op, filename = parse_req(req_plain)
                if verbose:
                    print(f"[server] REQ {op} {filename} session={session.session_id}")
                safe_name = os.path.basename(filename)
                path = os.path.join(storage, safe_name)

                if op == "GET":
                    if not os.path.exists(path):
                        err_payload = protect_payload(
                            session,
                            MsgType.ERROR,
                            session.local_seq,
                            0,
                            b"File not found",
                            outbound=True,
                        )
                        send_packet(sock, client_addr, Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload))
                        continue
                    sent = send_file(sock, client_addr, session, path, verbose=verbose)
                    print(f"[server] sent {sent} bytes -> {safe_name}")
                elif op == "PUT":
                    received = recv_file(sock, client_addr, session, path, verbose=verbose)
                    print(f"[server] received {received} bytes <- {safe_name}")
                else:
                    err_payload = protect_payload(
                        session,
                        MsgType.ERROR,
                        session.local_seq,
                        0,
                        b"Unknown operation",
                        outbound=True,
                    )
                    send_packet(sock, client_addr, Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload))
            except TimeoutError:
                print("[server] timeout; session dropped")
            except RDTError as exc:
                print(f"[server] protocol error: {exc}")
            except Exception as exc:
                print(f"[server] error: {exc}")
    except KeyboardInterrupt:
        print("\n[server] stopped by user")
    finally:
        sock.close()


def run_client(verbose: bool = False) -> None:
    server_host = prompt_text("Server host", "127.0.0.1")
    server_port = prompt_int("Server port", 9000, 1, 65535)
    op = prompt_client_op()
    remote_file = input("Remote filename: ").strip()
    if remote_file.lower() in QUIT_WORDS:
        raise KeyboardInterrupt
    local_file = input("Local file path: ").strip()
    if local_file.lower() in QUIT_WORDS:
        raise KeyboardInterrupt
    chunk_size = prompt_int("Chunk size", 1024, 128, 1024)

    if not remote_file:
        raise ValueError("Remote filename is required")
    if not local_file:
        raise ValueError("Local file path is required")

    server_addr = (server_host, server_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    try:
        session = client_handshake(sock, server_addr, chunk_size, verbose=verbose)
        req_payload = protect_payload(
            session,
            MsgType.REQ,
            session.local_seq,
            0,
            f"{op.upper()} {remote_file}".encode("utf-8"),
            outbound=True,
        )
        req = Packet(
            msg_type=MsgType.REQ,
            session_id=session.session_id,
            seq=session.local_seq,
            ack=0,
            payload=req_payload,
        )
        send_packet(sock, server_addr, req)
        if verbose:
            print(f"[client] REQ {op.upper()} {remote_file} session={session.session_id}")

        if op == "get":
            received = recv_file(sock, server_addr, session, local_file, verbose=verbose)
            print(f"[client] downloaded {received} bytes -> {local_file}")
        else:
            if not os.path.exists(local_file):
                raise FileNotFoundError(local_file)
            sent = send_file(sock, server_addr, session, local_file, verbose=verbose)
            print(f"[client] uploaded {sent} bytes <- {local_file}")
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Reliable UDP file transfer interactive launcher")
    parser.add_argument("--verbose", action="store_true", help="Show handshake/session/data debug logs")
    parser.add_argument("--secure-psk", default="", help="Enable secure mode with pre-shared key")
    args = parser.parse_args()
    configure_security(args.secure_psk or None)

    print("Reliable UDP File Transfer")
    print("Type q/quit/exit at prompts or press Ctrl+C anytime to stop.")
    if args.verbose:
        print("[app] verbose mode enabled")
    try:
        mode = prompt_mode()
        if mode == "server":
            set_wire_trace(True, "SERVER")
            run_server(verbose=args.verbose)
        else:
            set_wire_trace(True, "CLIENT")
            run_client(verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[app] terminated by user")


if __name__ == "__main__":
    main()
