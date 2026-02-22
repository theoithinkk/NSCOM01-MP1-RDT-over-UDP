import argparse
import os
import socket

from protocol import MsgType, Packet
from rdt import client_handshake, recv_file, send_file, send_packet


def main() -> None:
    parser = argparse.ArgumentParser(description="Reliable UDP file transfer client")
    parser.add_argument("--server-host", required=True)
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--op", choices=["get", "put"], required=True)
    parser.add_argument("--remote-file", required=True)
    parser.add_argument("--local-file", required=True)
    parser.add_argument("--chunk-size", type=int, default=1024)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    server_addr = (args.server_host, args.server_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    try:
        session = client_handshake(sock, server_addr, args.chunk_size, verbose=args.verbose)
        req = Packet(
            msg_type=MsgType.REQ,
            session_id=session.session_id,
            seq=session.local_seq,
            ack=0,
            payload=f"{args.op.upper()} {args.remote_file}".encode("utf-8"),
        )
        send_packet(sock, server_addr, req)
        if args.verbose:
            print(f"[client] REQ {args.op.upper()} {args.remote_file} session={session.session_id}")

        if args.op == "get":
            received = recv_file(sock, server_addr, session, args.local_file, verbose=args.verbose)
            print(f"[client] downloaded {received} bytes -> {args.local_file}")
        else:
            if not os.path.exists(args.local_file):
                raise FileNotFoundError(args.local_file)
            sent = send_file(sock, server_addr, session, args.local_file, verbose=args.verbose)
            print(f"[client] uploaded {sent} bytes <- {args.local_file}")
    except KeyboardInterrupt:
        print("\n[client] terminated by user")
    except Exception as exc:
        print(f"[client] error: {exc}")
        raise
    finally:
        sock.close()


if __name__ == "__main__":
    main()
