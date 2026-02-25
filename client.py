"""
Non-interactive CLI client for the Reliable UDP File Transfer protocol.

This client performs GET or PUT operations using command-line arguments
instead of the interactive launcher. It supports optional PSK-based
security and testing hooks for ACK delay/drop simulation.
"""

import argparse
import os
import socket

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
    send_file,
    send_packet,
    set_wire_trace,
)


def main() -> None:
    """Run the CLI entrypoint for non-interactive client mode.

    Steps performed:
    1. Parse command-line arguments.
    2. Configure security and testing hooks.
    3. Perform client handshake with the server.
    4. Send a REQ packet (GET or PUT).
    5. Transfer the file using the established session.
    """
    parser = argparse.ArgumentParser(description="Reliable UDP file transfer client")
    parser.add_argument("--server-host", required=True)
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--op", choices=["get", "put"], required=True)
    parser.add_argument("--remote-file", required=True)
    parser.add_argument("--local-file", required=True)
    parser.add_argument("--chunk-size", type=int, default=1024)
    parser.add_argument("--verbose", action="store_true")
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

    # Configure runtime security and testing behavior.
    configure_encryption(not args.no_encryption)
    configure_security(args.secure_psk or None)
    configure_test_drop_ack(args.test_drop_ack)
    configure_test_delay_ms(args.test_delay_ms)
    set_wire_trace(True, "CLIENT")

    server_addr = (args.server_host, args.server_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    try:
        log_phase("Client Handshake")
        session = client_handshake(sock, server_addr, args.chunk_size, verbose=args.verbose)
        log_session_parameters(session, server_addr)

        log_phase(f"Sending REQ: {args.op.upper()} {args.remote_file}")

        # Build protected REQ payload containing operation and filename.
        req_payload = protect_payload(
            session,
            MsgType.REQ,
            session.local_seq,
            0,
            f"{args.op.upper()} {args.remote_file}".encode("utf-8"),
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

        if args.verbose:
            print(f"[client] REQ {args.op.upper()} {args.remote_file} session={session.session_id}")

        if args.op == "get":
            log_phase("Receiving File (GET)")
            received = recv_file(sock, server_addr, session, args.local_file, verbose=args.verbose)
            print(f"[client] downloaded {received} bytes -> {args.local_file}")
        else:
            if not os.path.exists(args.local_file):
                raise FileNotFoundError(args.local_file)

            log_phase("Sending File (PUT)")
            sent = send_file(sock, server_addr, session, args.local_file, verbose=args.verbose)
            print(f"[client] uploaded {sent} bytes <- {args.local_file}")

    except KeyboardInterrupt:
        print("\n[client] terminated by user")
    except TimeoutError as exc:
        print(f"[client] timeout: {exc}")
    except FileNotFoundError as exc:
        print(f"[client] file not found: {exc}")
    except RDTError as exc:
        if str(exc).strip().lower() == "file not found":
            print("[client] file not found")
        else:
            print(f"[client] protocol error: {exc}")
    except Exception as exc:
        print(f"[client] error: {exc}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()