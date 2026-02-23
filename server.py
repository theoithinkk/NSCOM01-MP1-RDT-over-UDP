import argparse
import os
import socket
from typing import Tuple

from protocol import MsgType, Packet
from rdt import (
    RDTError,
    configure_test_drop_ack,
    configure_security,
    recv_file,
    recv_packet,
    send_file,
    send_packet,
    server_handshake,
    set_wire_trace,
    protect_payload,
    unprotect_payload,
)


def parse_req(payload: bytes) -> Tuple[str, str]:
    txt = payload.decode("utf-8", errors="replace").strip()
    parts = txt.split(maxsplit=1)
    if len(parts) != 2:
        raise ValueError("Invalid request")
    op, filename = parts
    return op.upper(), filename


def main() -> None:
    parser = argparse.ArgumentParser(description="Reliable UDP file transfer server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--storage", default="server_storage")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--secure-psk", default="", help="Require secure mode with pre-shared key")
    parser.add_argument(
        "--test-drop-ack",
        type=float,
        default=0.0,
        help="Test hook: probability [0.0-1.0] to drop outbound ACKs while receiving DATA",
    )
    args = parser.parse_args()
    configure_security(args.secure_psk or None)
    configure_test_drop_ack(args.test_drop_ack)
    set_wire_trace(True, "SERVER")

    os.makedirs(args.storage, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print(f"[server] listening on {args.host}:{args.port}")

    try:
        while True:
            try:
                session, client_addr = server_handshake(sock, verbose=args.verbose)
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
                if args.verbose:
                    print(f"[server] REQ {op} {filename} session={session.session_id}")
                safe_name = os.path.basename(filename)
                path = os.path.join(args.storage, safe_name)
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
                    sent = send_file(sock, client_addr, session, path, verbose=args.verbose)
                    print(f"[server] sent {sent} bytes -> {safe_name}")
                elif op == "PUT":
                    received = recv_file(sock, client_addr, session, path, verbose=args.verbose)
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
        print("\n[server] terminated by user")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
