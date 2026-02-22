import os
import random
import socket
from dataclasses import dataclass
from typing import Optional, Tuple

from protocol import MAX_PAYLOAD, MsgType, Packet, build_error


TIMEOUT_SECONDS = 0.8
MAX_RETRIES = 10


@dataclass
class Session:
    session_id: int
    local_seq: int
    remote_seq: int
    chunk_size: int


class RDTError(Exception):
    pass


def _trace(verbose: bool, message: str) -> None:
    if verbose:
        print(f"[rdt] {message}")


def recv_packet(sock: socket.socket, timeout: Optional[float] = None) -> Tuple[Packet, Tuple[str, int]]:
    sock.settimeout(timeout)
    data, addr = sock.recvfrom(4096)
    return Packet.decode(data), addr


def send_packet(sock: socket.socket, addr: Tuple[str, int], packet: Packet) -> None:
    sock.sendto(packet.encode(), addr)


def expect_ack(
    sock: socket.socket,
    addr: Tuple[str, int],
    session_id: int,
    expect_ack_for: int,
    verbose: bool = False,
) -> Packet:
    pkt, from_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
    if from_addr != addr:
        _trace(verbose, f"ignored ACK from unexpected peer {from_addr}")
        raise RDTError("Unexpected peer address")
    if pkt.session_id != session_id:
        _trace(verbose, f"session mismatch while waiting ACK: got={pkt.session_id} expected={session_id}")
        raise RDTError("Session mismatch")
    if pkt.msg_type == MsgType.ERROR:
        raise RDTError(pkt.payload.decode("utf-8", errors="replace"))
    if pkt.msg_type != MsgType.ACK or pkt.ack != expect_ack_for:
        _trace(
            verbose,
            f"unexpected packet while waiting ACK for seq={expect_ack_for}:"
            f" type={pkt.msg_type.name} ack={pkt.ack}",
        )
        raise RDTError("Expected ACK for sequence")
    _trace(verbose, f"received ACK ack={pkt.ack} for seq={expect_ack_for}")
    return pkt


def send_with_retransmit(
    sock: socket.socket,
    addr: Tuple[str, int],
    packet: Packet,
    expect_ack_for: int,
    verbose: bool = False,
) -> None:
    last_error = "Timeout"
    for attempt in range(1, MAX_RETRIES + 1):
        _trace(
            verbose,
            f"send {packet.msg_type.name} seq={packet.seq} attempt={attempt}/{MAX_RETRIES}",
        )
        send_packet(sock, addr, packet)
        try:
            expect_ack(sock, addr, packet.session_id, expect_ack_for, verbose=verbose)
            return
        except (socket.timeout, TimeoutError):
            last_error = "Timeout waiting for ACK"
            _trace(verbose, f"timeout waiting ACK for seq={expect_ack_for}")
        except RDTError as exc:
            last_error = str(exc)
            _trace(verbose, f"retransmit reason: {last_error}")
    raise TimeoutError(f"Retransmission failed: {last_error}")


def client_handshake(
    sock: socket.socket,
    server_addr: Tuple[str, int],
    chunk_size: int,
    verbose: bool = False,
) -> Session:
    client_isn = random.randint(1, 1_000_000)
    syn = Packet(
        msg_type=MsgType.SYN,
        session_id=0,
        seq=client_isn,
        ack=0,
        payload=f"chunk={chunk_size}".encode("utf-8"),
    )
    for attempt in range(1, MAX_RETRIES + 1):
        _trace(verbose, f"client handshake: send SYN isn={client_isn} attempt={attempt}/{MAX_RETRIES}")
        send_packet(sock, server_addr, syn)
        try:
            pkt, addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if addr != server_addr:
                _trace(verbose, f"client handshake: ignored packet from {addr}")
                continue
            if pkt.msg_type != MsgType.SYN_ACK:
                _trace(verbose, f"client handshake: expected SYN_ACK got {pkt.msg_type.name}")
                continue
            if pkt.ack != client_isn:
                _trace(verbose, f"client handshake: SYN_ACK ack mismatch got={pkt.ack} expected={client_isn}")
                continue
            session_id = pkt.session_id
            server_isn = pkt.seq
            _trace(
                verbose,
                f"client handshake: received SYN_ACK session={session_id} server_isn={server_isn}",
            )
            ack = Packet(MsgType.ACK, session_id, client_isn + 1, server_isn, b"")
            send_packet(sock, server_addr, ack)
            _trace(
                verbose,
                f"client handshake: sent ACK seq={client_isn + 1} ack={server_isn}; session established",
            )
            return Session(session_id, client_isn + 1, server_isn, chunk_size)
        except socket.timeout:
            _trace(verbose, "client handshake: timeout waiting SYN_ACK")
            continue
    raise TimeoutError("Handshake failed")


def server_handshake(sock: socket.socket, verbose: bool = False) -> Tuple[Session, Tuple[str, int]]:
    while True:
        pkt, addr = recv_packet(sock, timeout=None)
        if pkt.msg_type != MsgType.SYN:
            _trace(verbose, f"server handshake: ignored non-SYN packet type={pkt.msg_type.name} from {addr}")
            continue
        _trace(verbose, f"server handshake: received SYN from {addr} client_isn={pkt.seq}")
        chunk_size = MAX_PAYLOAD
        try:
            payload = pkt.payload.decode("utf-8", errors="ignore")
            if payload.startswith("chunk="):
                asked = int(payload.split("=", 1)[1])
                chunk_size = max(128, min(MAX_PAYLOAD, asked))
        except Exception:
            chunk_size = MAX_PAYLOAD
        session_id = random.randint(1, 2_147_483_647)
        server_isn = random.randint(1, 1_000_000)
        syn_ack = Packet(MsgType.SYN_ACK, session_id, server_isn, pkt.seq, f"chunk={chunk_size}".encode())
        _trace(
            verbose,
            f"server handshake: send SYN_ACK session={session_id} server_isn={server_isn} chunk={chunk_size}",
        )
        send_packet(sock, addr, syn_ack)
        try:
            ack, ack_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if ack_addr != addr:
                _trace(verbose, f"server handshake: ACK from unexpected peer {ack_addr}")
                continue
            if ack.msg_type != MsgType.ACK:
                _trace(verbose, f"server handshake: expected ACK got {ack.msg_type.name}")
                continue
            if ack.session_id != session_id or ack.ack != server_isn:
                _trace(
                    verbose,
                    "server handshake: ACK validation failed "
                    f"(session={ack.session_id}/{session_id}, ack={ack.ack}/{server_isn})",
                )
                continue
            _trace(
                verbose,
                f"server handshake: established session={session_id} peer={addr} client_seq={ack.seq}",
            )
            return Session(session_id, server_isn, ack.seq, chunk_size), addr
        except socket.timeout:
            _trace(verbose, "server handshake: timeout waiting final ACK")
            continue


def send_file(
    sock: socket.socket,
    addr: Tuple[str, int],
    session: Session,
    source_path: str,
    verbose: bool = False,
) -> int:
    seq = session.local_seq + 1
    sent_total = 0
    _trace(
        verbose,
        f"send_file: start session={session.session_id} path={source_path} chunk={session.chunk_size}",
    )
    with open(source_path, "rb") as f:
        while True:
            chunk = f.read(session.chunk_size)
            if not chunk:
                break
            packet = Packet(MsgType.DATA, session.session_id, seq, 0, chunk)
            send_with_retransmit(sock, addr, packet, expect_ack_for=seq, verbose=verbose)
            sent_total += len(chunk)
            seq += 1
    fin = Packet(MsgType.FIN, session.session_id, seq, 0, b"EOF")
    _trace(verbose, f"send_file: all DATA sent, sending FIN seq={seq}")
    for attempt in range(1, MAX_RETRIES + 1):
        send_packet(sock, addr, fin)
        try:
            pkt, from_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if from_addr != addr:
                _trace(verbose, f"send_file: ignored FIN_ACK from unexpected peer {from_addr}")
                continue
            if pkt.session_id != session.session_id:
                _trace(
                    verbose,
                    f"send_file: ignored packet with wrong session {pkt.session_id} expected={session.session_id}",
                )
                continue
            if pkt.msg_type == MsgType.FIN_ACK and pkt.ack == seq:
                session.local_seq = seq
                _trace(verbose, f"send_file: FIN confirmed on attempt={attempt}/{MAX_RETRIES}")
                return sent_total
        except socket.timeout:
            _trace(verbose, f"send_file: timeout waiting FIN_ACK attempt={attempt}/{MAX_RETRIES}")
            continue
    raise TimeoutError("FIN/FIN-ACK failed")


def recv_file(
    sock: socket.socket,
    addr: Tuple[str, int],
    session: Session,
    destination_path: str,
    verbose: bool = False,
) -> int:
    expected_seq = session.remote_seq + 1
    got_total = 0
    _trace(
        verbose,
        f"recv_file: start session={session.session_id} path={destination_path} expect_seq={expected_seq}",
    )
    os.makedirs(os.path.dirname(destination_path) or ".", exist_ok=True)
    with open(destination_path, "wb") as out:
        while True:
            pkt, from_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS * 3)
            if from_addr != addr:
                _trace(verbose, f"recv_file: ignored packet from unexpected peer {from_addr}")
                continue
            if pkt.session_id != session.session_id:
                err = build_error(session.session_id, 0, "Session mismatch")
                send_packet(sock, addr, err)
                _trace(
                    verbose,
                    f"recv_file: session mismatch got={pkt.session_id} expected={session.session_id}; sent ERROR",
                )
                continue
            if pkt.msg_type == MsgType.DATA:
                if pkt.seq == expected_seq:
                    out.write(pkt.payload)
                    got_total += len(pkt.payload)
                    ack = Packet(MsgType.ACK, session.session_id, session.local_seq, pkt.seq, b"")
                    send_packet(sock, addr, ack)
                    _trace(
                        verbose,
                        f"recv_file: accepted DATA seq={pkt.seq} bytes={len(pkt.payload)} sent ACK",
                    )
                    expected_seq += 1
                else:
                    last_ok = expected_seq - 1
                    ack = Packet(MsgType.ACK, session.session_id, session.local_seq, last_ok, b"")
                    send_packet(sock, addr, ack)
                    _trace(
                        verbose,
                        f"recv_file: out-of-order DATA seq={pkt.seq} expected={expected_seq}; re-ACK {last_ok}",
                    )
            elif pkt.msg_type == MsgType.FIN:
                fin_ack = Packet(MsgType.FIN_ACK, session.session_id, session.local_seq, pkt.seq, b"")
                send_packet(sock, addr, fin_ack)
                session.remote_seq = pkt.seq
                _trace(verbose, f"recv_file: received FIN seq={pkt.seq}, sent FIN_ACK")
                return got_total
            elif pkt.msg_type == MsgType.ERROR:
                raise RDTError(pkt.payload.decode("utf-8", errors="replace"))
            else:
                err = build_error(session.session_id, 0, "Unexpected packet type")
                send_packet(sock, addr, err)
                _trace(verbose, f"recv_file: unexpected packet type={pkt.msg_type.name}; sent ERROR")
