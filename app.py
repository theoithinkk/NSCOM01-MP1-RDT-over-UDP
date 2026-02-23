import argparse
import getpass
import os
import socket
from typing import Tuple

from protocol import MsgType, Packet
from rdt import (
    RDTError,
    client_handshake,
    configure_test_drop_ack,
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
LINE = "=" * 68
SUBLINE = "-" * 68


def parse_req(payload: bytes) -> Tuple[str, str]:
    txt = payload.decode("utf-8", errors="replace").strip()
    parts = txt.split(maxsplit=1)
    if len(parts) != 2:
        raise ValueError("Invalid request")
    op, filename = parts
    return op.upper(), filename


def show_banner() -> None:
    print(LINE)
    print(" Reliable UDP File Transfer")
    print(LINE)
    print(" Type q/quit/exit at prompts or press Ctrl+C anytime to stop.")
    print(SUBLINE)


def show_section(title: str) -> None:
    print(f"\n{SUBLINE}")
    print(f" {title}")
    print(SUBLINE)


def prompt_text(label: str, default: str) -> str:
    value = input(f"> {label} [{default}]: ").strip()
    if value.lower() in QUIT_WORDS:
        raise KeyboardInterrupt
    return value or default


def prompt_int(label: str, default: int, min_value: int = 1, max_value: int = 65535) -> int:
    while True:
        raw = input(f"> {label} [{default}]: ").strip()
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


def prompt_required_text(label: str) -> str:
    while True:
        value = input(f"> {label}: ").strip()
        if value.lower() in QUIT_WORDS:
            raise KeyboardInterrupt
        if value:
            return value
        print(f"{label} is required.")


def prompt_mode() -> str:
    while True:
        mode = input("> Select mode: [1] server, [2] client: ").strip().lower()
        if mode in QUIT_WORDS:
            raise KeyboardInterrupt
        if mode in ("1", "server", "s"):
            return "server"
        if mode in ("2", "client", "c"):
            return "client"
        print("Invalid choice. Type 1 for server or 2 for client.")


def prompt_client_op() -> str:
    while True:
        op = input("> Operation: [1] get, [2] put: ").strip().lower()
        if op in QUIT_WORDS:
            raise KeyboardInterrupt
        if op in ("1", "get", "g"):
            return "get"
        if op in ("2", "put", "p"):
            return "put"
        print("Invalid operation. Type 1 for get or 2 for put.")


def prompt_security_mode() -> str:
    while True:
        mode = input("> Security mode: [1] none, [2] psk-aead: ").strip().lower()
        if mode in QUIT_WORDS:
            raise KeyboardInterrupt
        if mode in ("", "1", "none", "n"):
            return "none"
        if mode in ("2", "psk", "psk-aead", "secure", "s"):
            return "psk-aead"
        print("Invalid choice. Type 1 for none or 2 for psk-aead.")


def prompt_psk() -> str:
    while True:
        secret = getpass.getpass("> Enter PSK (input hidden): ").strip()
        if secret.lower() in QUIT_WORDS:
            raise KeyboardInterrupt
        if secret:
            return secret
        print("PSK cannot be empty.")


def run_server(verbose: bool = False) -> None:
    show_section("Server Configuration")
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
    show_section("Client Configuration")
    server_host = prompt_text("Server host", "127.0.0.1")
    server_port = prompt_int("Server port", 9000, 1, 65535)
    op = prompt_client_op()
    if op == "get":
        print("  GET selected:")
        print("  - Remote filename = file name on the SERVER to download.")
        print("  - Local file path = where to save locally (folders allowed, e.g. downloads\\sample2.txt).")
        remote_file = prompt_required_text("Remote filename (on server)")
        local_file = prompt_required_text("Local save path (on this machine)")
    else:
        print("  PUT selected:")
        print("  - Local file path = existing file on THIS machine to upload.")
        print("  - Remote filename = name to store on SERVER.")
        remote_file = prompt_required_text("Remote filename (save as on server)")
        local_file = prompt_required_text("Local source file path (must exist)")
    chunk_size = prompt_int("Chunk size", 1024, 128, 1024)

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
    except TimeoutError as exc:
        print(f"[client] timeout: {exc}")
    except FileNotFoundError as exc:
        print(f"[client] file not found: {exc}")
    except RDTError as exc:
        if str(exc).strip().lower() == "file not found":
            print("[client] file not found")
        else:
            print(f"[client] protocol error: {exc}")
    except OSError as exc:
        print(f"[client] network error: {exc}")
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Reliable UDP file transfer interactive launcher")
    parser.add_argument("--verbose", action="store_true", help="Show handshake/session/data debug logs")
    parser.add_argument("--secure-psk", default="", help="Enable secure mode with pre-shared key")
    parser.add_argument(
        "--test-drop-ack",
        type=float,
        default=0.0,
        help="Test hook: probability [0.0-1.0] to drop outbound ACKs while receiving DATA",
    )
    args = parser.parse_args()

    show_banner()
    if args.verbose:
        print("[app] verbose mode enabled")
    try:
        show_section("Security Configuration")
        if args.secure_psk:
            configure_security(args.secure_psk)
            print("[app] security mode: psk-aead (from --secure-psk)")
        else:
            sec_mode = prompt_security_mode()
            if sec_mode == "psk-aead":
                configure_security(prompt_psk())
                print("[app] security mode: psk-aead")
            else:
                configure_security(None)
                print("[app] security mode: none")
        configure_test_drop_ack(args.test_drop_ack)

        show_section("Mode Selection")
        mode = prompt_mode()
        print(SUBLINE)
        print(f" Launching in {mode.upper()} mode")
        print(SUBLINE)
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
