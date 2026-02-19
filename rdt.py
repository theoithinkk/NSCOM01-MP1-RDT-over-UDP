import os
import random
import socket
import time
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


def recv_packet(sock: socket.socket, timeout: Optional[float] = None) -> Tuple[Packet, Tuple[str, int]]:
    sock.settimeout(timeout)
    data, addr = sock.recvfrom(4096)
    return Packet.decode(data), addr


def send_packet(sock: socket.socket, addr: Tuple[str, int], packet: Packet) -> None:
    sock.sendto(packet.encode(), addr)


def expect_ack(sock: socket.socket, addr: Tuple[str, int], session_id: int, expect_ack_for: int) -> Packet:
    pkt, from_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
    if from_addr != addr:
        raise RDTError("Unexpected peer address")
    if pkt.session_id != session_id:
        raise RDTError("Session mismatch")
    if pkt.msg_type == MsgType.ERROR:
        raise RDTError(pkt.payload.decode("utf-8", errors="replace"))
    if pkt.msg_type != MsgType.ACK or pkt.ack != expect_ack_for:
        raise RDTError("Expected ACK for sequence")
    return pkt


def send_with_retransmit(
    sock: socket.socket,
    addr: Tuple[str, int],
    packet: Packet,
    expect_ack_for: int,
) -> None:
    last_error = "Timeout"
    for _ in range(MAX_RETRIES):
        send_packet(sock, addr, packet)
        try:
            expect_ack(sock, addr, packet.session_id, expect_ack_for)
            return
        except (socket.timeout, TimeoutError):
            last_error = "Timeout waiting for ACK"
        except RDTError as exc:
            last_error = str(exc)
    raise TimeoutError(f"Retransmission failed: {last_error}")


def client_handshake(sock: socket.socket, server_addr: Tuple[str, int], chunk_size: int) -> Session:
    client_isn = random.randint(1, 1_000_000)
    syn = Packet(
        msg_type=MsgType.SYN,
        session_id=0,
        seq=client_isn,
        ack=0,
        payload=f"chunk={chunk_size}".encode("utf-8"),
    )
    for _ in range(MAX_RETRIES):
        send_packet(sock, server_addr, syn)
        try:
            pkt, addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if addr != server_addr:
                continue
            if pkt.msg_type != MsgType.SYN_ACK:
                continue
            if pkt.ack != client_isn:
                continue
            session_id = pkt.session_id
            server_isn = pkt.seq
            ack = Packet(MsgType.ACK, session_id, client_isn + 1, server_isn, b"")
            send_packet(sock, server_addr, ack)
            return Session(session_id, client_isn + 1, server_isn, chunk_size)
        except socket.timeout:
            continue
    raise TimeoutError("Handshake failed")


def server_handshake(sock: socket.socket) -> Tuple[Session, Tuple[str, int]]:
    while True:
        pkt, addr = recv_packet(sock, timeout=None)
        if pkt.msg_type != MsgType.SYN:
            continue
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
        send_packet(sock, addr, syn_ack)
        try:
            ack, ack_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if ack_addr != addr:
                continue
            if ack.msg_type != MsgType.ACK:
                continue
            if ack.session_id != session_id or ack.ack != server_isn:
                continue
            return Session(session_id, server_isn, ack.seq, chunk_size), addr
        except socket.timeout:
            continue


def send_file(sock: socket.socket, addr: Tuple[str, int], session: Session, source_path: str) -> int:
    seq = session.local_seq + 1
    sent_total = 0
    with open(source_path, "rb") as f:
        while True:
            chunk = f.read(session.chunk_size)
            if not chunk:
                break
            packet = Packet(MsgType.DATA, session.session_id, seq, 0, chunk)
            send_with_retransmit(sock, addr, packet, expect_ack_for=seq)
            sent_total += len(chunk)
            seq += 1
    fin = Packet(MsgType.FIN, session.session_id, seq, 0, b"EOF")
    for _ in range(MAX_RETRIES):
        send_packet(sock, addr, fin)
        try:
            pkt, from_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if from_addr != addr:
                continue
            if pkt.session_id != session.session_id:
                continue
            if pkt.msg_type == MsgType.FIN_ACK and pkt.ack == seq:
                session.local_seq = seq
                return sent_total
        except socket.timeout:
            continue
    raise TimeoutError("FIN/FIN-ACK failed")


def recv_file(sock: socket.socket, addr: Tuple[str, int], session: Session, destination_path: str) -> int:
    expected_seq = session.remote_seq + 1
    got_total = 0
    os.makedirs(os.path.dirname(destination_path) or ".", exist_ok=True)
    with open(destination_path, "wb") as out:
        while True:
            pkt, from_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS * 3)
            if from_addr != addr:
                continue
            if pkt.session_id != session.session_id:
                err = build_error(session.session_id, 0, "Session mismatch")
                send_packet(sock, addr, err)
                continue
            if pkt.msg_type == MsgType.DATA:
                if pkt.seq == expected_seq:
                    out.write(pkt.payload)
                    got_total += len(pkt.payload)
                    ack = Packet(MsgType.ACK, session.session_id, session.local_seq, pkt.seq, b"")
                    send_packet(sock, addr, ack)
                    expected_seq += 1
                else:
                    last_ok = expected_seq - 1
                    ack = Packet(MsgType.ACK, session.session_id, session.local_seq, last_ok, b"")
                    send_packet(sock, addr, ack)
            elif pkt.msg_type == MsgType.FIN:
                fin_ack = Packet(MsgType.FIN_ACK, session.session_id, session.local_seq, pkt.seq, b"")
                send_packet(sock, addr, fin_ack)
                session.remote_seq = pkt.seq
                return got_total
            elif pkt.msg_type == MsgType.ERROR:
                raise RDTError(pkt.payload.decode("utf-8", errors="replace"))
            else:
                err = build_error(session.session_id, 0, "Unexpected packet type")
                send_packet(sock, addr, err)
