import argparse
import os
import socket
from typing import Tuple

from protocol import MsgType, Packet, build_error
from rdt import RDTError, recv_file, recv_packet, send_file, send_packet, server_handshake


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
    args = parser.parse_args()

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
                    send_packet(sock, client_addr, build_error(session.session_id, 0, "Session mismatch"))
                    continue
                op, filename = parse_req(req_pkt.payload)
                if args.verbose:
                    print(f"[server] REQ {op} {filename} session={session.session_id}")
                safe_name = os.path.basename(filename)
                path = os.path.join(args.storage, safe_name)
                if op == "GET":
                    if not os.path.exists(path):
                        send_packet(sock, client_addr, build_error(session.session_id, 0, "File not found"))
                        continue
                    sent = send_file(sock, client_addr, session, path, verbose=args.verbose)
                    print(f"[server] sent {sent} bytes -> {safe_name}")
                elif op == "PUT":
                    received = recv_file(sock, client_addr, session, path, verbose=args.verbose)
                    print(f"[server] received {received} bytes <- {safe_name}")
                else:
                    send_packet(sock, client_addr, build_error(session.session_id, 0, "Unknown operation"))
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
