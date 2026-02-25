"""
Interactive launcher for a Reliable UDP File Transfer protocol (GET/PUT).

This script provides a simple terminal UI to run either a server or client.
It also supports optional PSK-based secure mode and test hooks (ACK drop/delay)
to simulate network conditions.
"""

import argparse
import getpass
import os
import socket
from typing import Tuple

from protocol import MsgType, Packet
from rdt import (
    RDTError,
    client_handshake,
    configure_encryption,
    configure_test_delay_ms,
    configure_test_drop_ack,
    configure_security,
    log_phase,
    log_session_parameters,
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
LINE = "=" * 44
COLOR_ENABLED = os.environ.get("NO_COLOR") is None
ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_CYAN = "\x1b[96m"
ANSI_BLUE = "\x1b[94m"
ANSI_DIM = "\x1b[2m"


def _paint(text: str, *styles: str) -> str:
    """Apply ANSI styles to text unless coloring is disabled."""
    if not COLOR_ENABLED or not styles:
        return text
    return "".join(styles) + text + ANSI_RESET


def parse_req(payload: bytes) -> Tuple[str, str]:
    """Parse a REQ payload into (operation, filename).

    Expected format (UTF-8 text): "<OP> <FILENAME>"
    - OP is typically GET or PUT (case-insensitive).
    - FILENAME may include spaces only if encoded accordingly; here we split once.
    """
    txt = payload.decode("utf-8", errors="replace").strip()
    parts = txt.split(maxsplit=1)
    if len(parts) != 2:
        raise ValueError("Invalid request")
    op, filename = parts
    return op.upper(), filename


def show_banner() -> None:
    """Print the launcher banner and basic usage hint."""
    print()
    print(_paint("=== File Transfer Protocol ===", ANSI_CYAN))
    print(_paint(" Reliable UDP File Transfer", ANSI_BLUE))
    print(_paint(LINE, ANSI_DIM))
    print(" Type q/quit/exit at prompts or press Ctrl+C anytime to stop.")


def show_section(title: str) -> None:
    """Print a titled section divider."""
    print(f"\n{_paint(f'=== {title} ===', ANSI_CYAN)}")


def prompt_text(label: str, default: str) -> str:
    """Prompt for text input with a default value; supports quit words."""
    value = input(f"> {label} [{default}]: ").strip()
    if value.lower() in QUIT_WORDS:
        raise KeyboardInterrupt
    return value or default


def prompt_int(label: str, default: int, min_value: int = 1, max_value: int = 65535) -> int:
    """Prompt for an integer within [min_value, max_value]; supports quit words."""
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
    """Prompt until a non-empty value is provided; supports quit words."""
    while True:
        value = input(f"> {label}: ").strip()
        if value.lower() in QUIT_WORDS:
            raise KeyboardInterrupt
        if value:
            return value
        print(f"{label} is required.")


def prompt_mode() -> str:
    """Prompt for runtime mode selection: 'server' or 'client'."""
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
    """Prompt for transfer operation: 'get' or 'put'."""
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
    """Prompt for security mode selection: 'none' or 'psk-aead'."""
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
    """Prompt for a PSK using hidden input; supports quit words."""
    while True:
        secret = getpass.getpass("> Enter PSK (input hidden): ").strip()
        if secret.lower() in QUIT_WORDS:
            raise KeyboardInterrupt
        if secret:
            return secret
        print("PSK cannot be empty.")


def run_server(verbose: bool = False) -> None:
    """Run the interactive server workflow.
    The server accepts one session at a time:
    - Performs a handshake to establish session parameters.
    - Waits for a REQ (GET/PUT) from the same peer address.
    - Sends/receives a file using the established session.
    """
    show_section("Server Configuration")
    host = prompt_text("Server host", "0.0.0.0")
    port = prompt_int("Server port", 9000, 1, 65535)
    storage = prompt_text("Storage directory", "server_storage")

    os.makedirs(storage, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    log_phase("Server Ready")
    print(f"[server] listening on {host}:{port}")

    try:
        while True:
            try:
                session, client_addr = server_handshake(sock, verbose=verbose)
                print(f"[server] session={session.session_id} peer={client_addr}")
                log_session_parameters(session, client_addr)

                log_phase("Waiting for REQ")
                req_pkt, req_addr = recv_packet(sock, timeout=5.0)

                # Ignore stray packets from other peers while a session is active.
                if req_addr != client_addr:
                    continue

                # Enforce session + message type before trying to decrypt/parse.
                if req_pkt.session_id != session.session_id or req_pkt.msg_type != MsgType.REQ:
                    err_payload = protect_payload(
                        session,
                        MsgType.ERROR,
                        session.local_seq,
                        0,
                        b"Session mismatch",
                        outbound=True,
                    )
                    send_packet(
                        sock,
                        client_addr,
                        Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload),
                    )
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
                log_phase(f"Transfer Request: {op} {filename}")

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
                        send_packet(
                            sock,
                            client_addr,
                            Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload),
                        )
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
                    send_packet(
                        sock,
                        client_addr,
                        Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload),
                    )

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
    """Run the interactive client workflow for GET/PUT.
    - Performs handshake with the server.
    - Sends a REQ indicating GET/PUT + remote filename.
    - Transfers file in the chosen direction using the established session.
    """
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
        log_phase("Client Handshake")
        session = client_handshake(sock, server_addr, chunk_size, verbose=verbose)
        log_session_parameters(session, server_addr)

        log_phase(f"Sending REQ: {op.upper()} {remote_file}")
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
            log_phase("Receiving File (GET)")
            received = recv_file(sock, server_addr, session, local_file, verbose=verbose)
            print(f"[client] downloaded {received} bytes -> {local_file}")
        else:
            if not os.path.exists(local_file):
                raise FileNotFoundError(local_file)
            log_phase("Sending File (PUT)")
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
    """Parse CLI flags, configure security/test hooks, and launch server/client mode."""
    parser = argparse.ArgumentParser(description="Reliable UDP file transfer interactive launcher")
    parser.add_argument("--verbose", action="store_true", help="Show handshake/session/data debug logs")
    parser.add_argument("--secure-psk", default="", help="Enable secure mode with pre-shared key")
    parser.add_argument("--no-encryption", action="store_true", help="Disable AEAD payload encryption for debugging")
    parser.add_argument(
        "--test-drop-ack",
        type=float,
        default=0.0,
        help="Test hook: probability [0.0-1.0] to drop outbound ACKs while receiving DATA",
    )
    parser.add_argument(
        "--test-delay-ms",
        type=int,
        default=0,
        help="Test hook: fixed millisecond delay before outbound ACKs while receiving DATA",
    )
    args = parser.parse_args()

    show_banner()
    if args.verbose:
        print("[app] verbose mode enabled")

    try:
        show_section("Security Configuration")

        configure_encryption(not args.no_encryption)
        secure_label = "psk-aead" if not args.no_encryption else "psk-auth"
        if args.no_encryption:
            print("[app] payload encryption: disabled (--no-encryption)")

        if args.secure_psk:
            configure_security(args.secure_psk)
            print(f"[app] security mode: {secure_label} (from --secure-psk)")
        else:
            sec_mode = prompt_security_mode()
            if sec_mode == "psk-aead":
                configure_security(prompt_psk())
                print(f"[app] security mode: {secure_label}")
            else:
                configure_security(None)
                print("[app] security mode: none")

        configure_test_drop_ack(args.test_drop_ack)
        configure_test_delay_ms(args.test_delay_ms)

        show_section("Mode Selection")
        mode = prompt_mode()
        print(_paint(f"Launching in {mode.upper()} mode", ANSI_BLUE))

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