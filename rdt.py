import hashlib
import hmac
import os
import random
import socket
import struct
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from protocol import MAX_PAYLOAD, MsgType, Packet, build_error


TIMEOUT_SECONDS = 0.8
MAX_RETRIES = 10
WIRE_TRACE_ENABLED = False
WIRE_TRACE_ROLE = "APP"
SECURITY_STATUS_PRINTED = False
COLOR_ENABLED = os.environ.get("NO_COLOR") is None
SECURE_PSK_BYTES: Optional[bytes] = None
TEST_DROP_ACK_RATE = 0.0

ANSI_RESET = "\x1b[0m"
ANSI_DIM = "\x1b[2m"
ANSI_BOLD = "\x1b[1m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_BLUE = "\x1b[34m"
ANSI_MAGENTA = "\x1b[35m"
ANSI_CYAN = "\x1b[36m"
ANSI_WHITE = "\x1b[37m"


@dataclass
class Session:
    session_id: int
    local_seq: int
    remote_seq: int
    chunk_size: int
    is_client: bool
    secure_key: Optional[bytes] = None


class RDTError(Exception):
    pass


def _paint(text: str, *styles: str) -> str:
    if not COLOR_ENABLED or not styles:
        return text
    return "".join(styles) + text + ANSI_RESET


def _msg_style(msg_type: MsgType) -> str:
    return {
        MsgType.SYN: ANSI_BLUE,
        MsgType.SYN_ACK: ANSI_MAGENTA,
        MsgType.ACK: ANSI_CYAN,
        MsgType.DATA: ANSI_WHITE,
        MsgType.FIN: ANSI_YELLOW,
        MsgType.FIN_ACK: ANSI_GREEN,
        MsgType.ERROR: ANSI_RED,
        MsgType.REQ: ANSI_BLUE,
    }.get(msg_type, ANSI_WHITE)


def _trace(verbose: bool, message: str) -> None:
    if verbose:
        print(_paint(f"[rdt] {message}", ANSI_DIM, ANSI_CYAN))


def _security_log(message: str, ok: bool = True) -> None:
    color = ANSI_GREEN if ok else ANSI_RED
    print(_paint(f"[SECURITY] {message}", ANSI_BOLD, color))


def _retransmit_log(message: str) -> None:
    print(_paint(f"[RETRANSMIT] {message}", ANSI_BOLD, ANSI_YELLOW))


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401
    except Exception as exc:
        raise RDTError(
            "Secure mode requires 'cryptography'. Install with: py -3 -m pip install cryptography"
        ) from exc


def configure_security(psk: Optional[str]) -> None:
    global SECURE_PSK_BYTES
    if psk:
        _require_crypto()
        SECURE_PSK_BYTES = psk.encode("utf-8")
    else:
        SECURE_PSK_BYTES = None


def security_enabled() -> bool:
    return SECURE_PSK_BYTES is not None


def configure_test_drop_ack(rate: float) -> None:
    global TEST_DROP_ACK_RATE
    TEST_DROP_ACK_RATE = max(0.0, min(1.0, rate))


def set_wire_trace(enabled: bool, role: str = "APP") -> None:
    global WIRE_TRACE_ENABLED, WIRE_TRACE_ROLE, SECURITY_STATUS_PRINTED
    WIRE_TRACE_ENABLED = enabled
    WIRE_TRACE_ROLE = role.upper()
    if enabled and not SECURITY_STATUS_PRINTED:
        if security_enabled():
            print(
                _paint(
                    "[SECURITY] integrity=crc32+sha256+aead, encryption=enabled, authentication=psk-hmac",
                    ANSI_BOLD,
                    ANSI_YELLOW,
                )
            )
        else:
            print(
                _paint(
                    "[SECURITY] integrity=crc32+sha256, encryption=disabled, authentication=disabled",
                    ANSI_BOLD,
                    ANSI_YELLOW,
                )
            )
        SECURITY_STATUS_PRINTED = True


def _format_sent_packet(packet: Packet) -> str:
    return f"type={_paint(packet.msg_type.name, ANSI_BOLD, _msg_style(packet.msg_type))} segnum={packet.seq}"


def _format_received_packet(packet: Packet) -> str:
    if packet.msg_type == MsgType.DATA:
        return (
            f"type={_paint('DATA', ANSI_BOLD, _msg_style(packet.msg_type))} "
            f"segnum={packet.seq} payload_length={len(packet.payload)}"
        )
    return f"type={_paint(packet.msg_type.name, ANSI_BOLD, _msg_style(packet.msg_type))} segnum={packet.seq}"


def _parse_kv_payload(payload: bytes) -> Dict[str, str]:
    text = payload.decode("utf-8", errors="ignore").strip()
    out: Dict[str, str] = {}
    for part in text.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _derive_session_key(psk: bytes, cnonce: bytes, snonce: bytes, session_id: int) -> bytes:
    # HKDF-like derivation via HMAC-SHA256 for a single 32-byte key.
    salt = cnonce + snonce + struct.pack("!I", session_id)
    return hmac.new(psk, b"rdt-session-key|" + salt, hashlib.sha256).digest()


def _server_proof(psk: bytes, cnonce: bytes, snonce: bytes, client_isn: int, server_isn: int, session_id: int) -> str:
    material = b"server-proof|" + cnonce + snonce + struct.pack("!III", client_isn, server_isn, session_id)
    return hmac.new(psk, material, hashlib.sha256).hexdigest()


def _client_proof(psk: bytes, cnonce: bytes, snonce: bytes, client_isn: int, server_isn: int, session_id: int) -> str:
    material = b"client-proof|" + cnonce + snonce + struct.pack("!III", client_isn, server_isn, session_id)
    return hmac.new(psk, material, hashlib.sha256).hexdigest()


def _nonce(session_id: int, seq: int, from_client: bool) -> bytes:
    # 12-byte nonce: session_id(4) + dir(1) + seq(4) + pad(3)
    direction = b"\x01" if from_client else b"\x00"
    return struct.pack("!I", session_id) + direction + struct.pack("!I", seq) + b"\x00\x00\x00"


def _aad(msg_type: MsgType, session_id: int, seq: int, ack: int) -> bytes:
    return struct.pack("!BIII", int(msg_type), session_id, seq, ack)


def _encrypt_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool) -> bytes:
    if not session.secure_key:
        return payload
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from_client = session.is_client if outbound else (not session.is_client)
    cipher = ChaCha20Poly1305(session.secure_key)
    ciphertext = cipher.encrypt(_nonce(session.session_id, seq, from_client), payload, _aad(msg_type, session.session_id, seq, ack))
    return ciphertext


def _decrypt_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool) -> bytes:
    if not session.secure_key:
        return payload
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from_client = session.is_client if outbound else (not session.is_client)
    cipher = ChaCha20Poly1305(session.secure_key)
    try:
        return cipher.decrypt(_nonce(session.session_id, seq, from_client), payload, _aad(msg_type, session.session_id, seq, ack))
    except Exception as exc:
        raise RDTError("AEAD authentication failed") from exc


def _build_fin_payload(total_size: int, digest_hex: str) -> bytes:
    return f"EOF|size={total_size}|sha256={digest_hex}".encode("utf-8")


def _parse_fin_payload(payload: bytes) -> Tuple[Optional[int], Optional[str]]:
    try:
        text = payload.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None, None
    if not text.startswith("EOF"):
        return None, None
    parts = text.split("|")
    size_value: Optional[int] = None
    hash_value: Optional[str] = None
    for part in parts[1:]:
        if part.startswith("size="):
            try:
                size_value = int(part.split("=", 1)[1])
            except ValueError:
                size_value = None
        elif part.startswith("sha256="):
            hash_value = part.split("=", 1)[1].strip().lower()
    return size_value, hash_value


def _is_connection_reset_error(exc: BaseException) -> bool:
    if isinstance(exc, ConnectionResetError):
        return True
    if not isinstance(exc, OSError):
        return False
    return getattr(exc, "winerror", None) == 10054


def recv_packet(sock: socket.socket, timeout: Optional[float] = None) -> Tuple[Packet, Tuple[str, int]]:
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(4096)
    except OSError as exc:
        # On Windows UDP sockets, peer shutdown can surface as WSAECONNRESET.
        # Map it to timeout-style handling so retry logic can continue gracefully.
        if _is_connection_reset_error(exc):
            raise socket.timeout("Peer became unreachable") from exc
        raise
    try:
        packet = Packet.decode(data)
    except ValueError as exc:
        if WIRE_TRACE_ENABLED and "Checksum mismatch" in str(exc):
            _security_log("CRC32 verification failed (packet dropped)", ok=False)
        raise
    if WIRE_TRACE_ENABLED:
        print(
            f"[{WIRE_TRACE_ROLE}] Message received from={addr} "
            f"{_format_received_packet(packet)} {_paint('integrity=crc32_ok', ANSI_GREEN)}"
        )
    return packet, addr


def send_packet(sock: socket.socket, addr: Tuple[str, int], packet: Packet) -> None:
    if WIRE_TRACE_ENABLED:
        print(f"[{WIRE_TRACE_ROLE}] Message sent to={addr} {_format_sent_packet(packet)}")
    sock.sendto(packet.encode(), addr)


def protect_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool = True) -> bytes:
    return _encrypt_payload(session, msg_type, seq, ack, payload, outbound=outbound)


def unprotect_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool = False) -> bytes:
    return _decrypt_payload(session, msg_type, seq, ack, payload, outbound=outbound)


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
        if attempt > 1:
            _retransmit_log(
                f"retrying {packet.msg_type.name} seq={packet.seq} attempt={attempt}/{MAX_RETRIES}"
            )
        _trace(
            verbose,
            f"send {packet.msg_type.name} seq={packet.seq} attempt={attempt}/{MAX_RETRIES}",
        )
        send_packet(sock, addr, packet)
        try:
            expect_ack(sock, addr, packet.session_id, expect_ack_for, verbose=verbose)
            if attempt > 1:
                _retransmit_log(
                    f"recovered {packet.msg_type.name} seq={packet.seq} on attempt={attempt}/{MAX_RETRIES}"
                )
            return
        except (socket.timeout, TimeoutError):
            last_error = "Timeout waiting for ACK"
            _trace(verbose, f"timeout waiting ACK for seq={expect_ack_for}")
            _retransmit_log(f"timeout waiting ACK for seq={expect_ack_for}")
        except RDTError as exc:
            last_error = str(exc)
            _trace(verbose, f"retransmit reason: {last_error}")
            _retransmit_log(f"retry reason for seq={expect_ack_for}: {last_error}")
    raise TimeoutError(f"Retransmission failed: {last_error}")


def client_handshake(
    sock: socket.socket,
    server_addr: Tuple[str, int],
    chunk_size: int,
    verbose: bool = False,
) -> Session:
    client_isn = random.randint(1, 1_000_000)
    cnonce = os.urandom(16)
    secure = security_enabled()
    syn_payload = f"chunk={chunk_size};secure={1 if secure else 0}".encode("utf-8")
    if secure:
        syn_payload += f";cnonce={cnonce.hex()}".encode("utf-8")

    syn = Packet(
        msg_type=MsgType.SYN,
        session_id=0,
        seq=client_isn,
        ack=0,
        payload=syn_payload,
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
            secure_key: Optional[bytes] = None
            ack_payload = b""

            if secure:
                fields = _parse_kv_payload(pkt.payload)
                snonce_hex = fields.get("snonce")
                sproof = fields.get("sproof")
                if not snonce_hex or not sproof:
                    raise RDTError("Secure handshake failed: missing server proof")
                snonce = bytes.fromhex(snonce_hex)
                assert SECURE_PSK_BYTES is not None
                expect_sproof = _server_proof(SECURE_PSK_BYTES, cnonce, snonce, client_isn, server_isn, session_id)
                if not hmac.compare_digest(expect_sproof, sproof):
                    raise RDTError("Secure handshake failed: invalid server proof")
                cproof = _client_proof(SECURE_PSK_BYTES, cnonce, snonce, client_isn, server_isn, session_id)
                ack_payload = f"cproof={cproof}".encode("utf-8")
                secure_key = _derive_session_key(SECURE_PSK_BYTES, cnonce, snonce, session_id)
                _security_log("PSK authentication passed")

            ack = Packet(MsgType.ACK, session_id, client_isn + 1, server_isn, ack_payload)
            send_packet(sock, server_addr, ack)
            return Session(session_id, client_isn + 1, server_isn, chunk_size, is_client=True, secure_key=secure_key)
        except socket.timeout:
            continue
    raise TimeoutError("Handshake failed")


def server_handshake(sock: socket.socket, verbose: bool = False) -> Tuple[Session, Tuple[str, int]]:
    while True:
        pkt, addr = recv_packet(sock, timeout=None)
        if pkt.msg_type != MsgType.SYN:
            continue

        fields = _parse_kv_payload(pkt.payload)
        chunk_size = MAX_PAYLOAD
        try:
            if "chunk" in fields:
                asked = int(fields["chunk"])
                chunk_size = max(128, min(MAX_PAYLOAD, asked))
        except Exception:
            chunk_size = MAX_PAYLOAD

        secure_requested = fields.get("secure", "0") == "1"
        if secure_requested and not security_enabled():
            err = build_error(0, 0, "Secure mode requested but server PSK not configured")
            send_packet(sock, addr, err)
            continue
        if not secure_requested and security_enabled():
            err = build_error(0, 0, "Server requires secure mode")
            send_packet(sock, addr, err)
            continue

        session_id = random.randint(1, 2_147_483_647)
        server_isn = random.randint(1, 1_000_000)
        secure_key: Optional[bytes] = None
        syn_ack_payload = f"chunk={chunk_size}".encode("utf-8")

        cnonce = b""
        snonce = b""
        if secure_requested:
            cnonce_hex = fields.get("cnonce")
            if not cnonce_hex:
                err = build_error(0, 0, "Secure handshake missing cnonce")
                send_packet(sock, addr, err)
                continue
            cnonce = bytes.fromhex(cnonce_hex)
            snonce = os.urandom(16)
            assert SECURE_PSK_BYTES is not None
            sproof = _server_proof(SECURE_PSK_BYTES, cnonce, snonce, pkt.seq, server_isn, session_id)
            syn_ack_payload += f";snonce={snonce.hex()};sproof={sproof}".encode("utf-8")

        syn_ack = Packet(MsgType.SYN_ACK, session_id, server_isn, pkt.seq, syn_ack_payload)
        send_packet(sock, addr, syn_ack)

        try:
            ack, ack_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if ack_addr != addr:
                continue
            if ack.msg_type != MsgType.ACK:
                continue
            if ack.session_id != session_id or ack.ack != server_isn:
                continue

            if secure_requested:
                afields = _parse_kv_payload(ack.payload)
                cproof = afields.get("cproof")
                if not cproof:
                    err = build_error(session_id, 0, "Secure handshake missing client proof")
                    send_packet(sock, addr, err)
                    continue
                assert SECURE_PSK_BYTES is not None
                expect = _client_proof(SECURE_PSK_BYTES, cnonce, snonce, pkt.seq, server_isn, session_id)
                if not hmac.compare_digest(expect, cproof):
                    err = build_error(session_id, 0, "Secure handshake invalid client proof")
                    send_packet(sock, addr, err)
                    continue
                secure_key = _derive_session_key(SECURE_PSK_BYTES, cnonce, snonce, session_id)
                _security_log("PSK authentication passed")

            return Session(session_id, server_isn, ack.seq, chunk_size, is_client=False, secure_key=secure_key), addr
        except socket.timeout:
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
    hasher = hashlib.sha256()

    chunk_cap = session.chunk_size
    if session.secure_key:
        # AEAD tag overhead.
        chunk_cap = max(1, session.chunk_size - 16)

    with open(source_path, "rb") as f:
        while True:
            chunk = f.read(chunk_cap)
            if not chunk:
                break
            hasher.update(chunk)
            payload = _encrypt_payload(session, MsgType.DATA, seq, 0, chunk, outbound=True)
            packet = Packet(MsgType.DATA, session.session_id, seq, 0, payload)
            send_with_retransmit(sock, addr, packet, expect_ack_for=seq, verbose=verbose)
            sent_total += len(chunk)
            seq += 1

    digest_hex = hasher.hexdigest()
    fin_plain = _build_fin_payload(sent_total, digest_hex)
    fin_payload = _encrypt_payload(session, MsgType.FIN, seq, 0, fin_plain, outbound=True)
    fin = Packet(MsgType.FIN, session.session_id, seq, 0, fin_payload)

    for _ in range(MAX_RETRIES):
        send_packet(sock, addr, fin)
        try:
            pkt, from_addr = recv_packet(sock, timeout=TIMEOUT_SECONDS)
            if from_addr != addr:
                continue
            if pkt.session_id != session.session_id:
                continue
            if pkt.msg_type == MsgType.ERROR:
                err_payload = _decrypt_payload(session, MsgType.ERROR, pkt.seq, pkt.ack, pkt.payload, outbound=False)
                raise RDTError(err_payload.decode("utf-8", errors="replace"))
            if pkt.msg_type == MsgType.FIN_ACK and pkt.ack == seq:
                session.local_seq = seq
                return sent_total
        except socket.timeout:
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
    hasher = hashlib.sha256()
    out = None
    try:
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
                    plain = _decrypt_payload(session, MsgType.DATA, pkt.seq, pkt.ack, pkt.payload, outbound=False)
                    if out is None:
                        os.makedirs(os.path.dirname(destination_path) or ".", exist_ok=True)
                        out = open(destination_path, "wb")
                    out.write(plain)
                    got_total += len(plain)
                    hasher.update(plain)
                    ack = Packet(MsgType.ACK, session.session_id, session.local_seq, pkt.seq, b"")
                    if TEST_DROP_ACK_RATE > 0.0 and random.random() < TEST_DROP_ACK_RATE:
                        _trace(verbose, f"test hook dropped ACK for seq={pkt.seq}")
                    else:
                        send_packet(sock, addr, ack)
                    expected_seq += 1
                else:
                    last_ok = expected_seq - 1
                    ack = Packet(MsgType.ACK, session.session_id, session.local_seq, last_ok, b"")
                    if TEST_DROP_ACK_RATE > 0.0 and random.random() < TEST_DROP_ACK_RATE:
                        _trace(verbose, f"test hook dropped duplicate ACK for seq={last_ok}")
                    else:
                        send_packet(sock, addr, ack)

            elif pkt.msg_type == MsgType.FIN:
                fin_plain = _decrypt_payload(session, MsgType.FIN, pkt.seq, pkt.ack, pkt.payload, outbound=False)
                expected_size, expected_hash = _parse_fin_payload(fin_plain)
                actual_hash = hasher.hexdigest()

                if expected_size is not None and expected_size != got_total:
                    err_payload = _encrypt_payload(
                        session,
                        MsgType.ERROR,
                        session.local_seq,
                        0,
                        b"File size mismatch",
                        outbound=True,
                    )
                    err = Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload)
                    send_packet(sock, addr, err)
                    _security_log(
                        f"SHA-256 verification failed (size mismatch expected={expected_size} actual={got_total})",
                        ok=False,
                    )
                    raise RDTError("File size mismatch")

                if expected_hash and expected_hash != actual_hash:
                    err_payload = _encrypt_payload(
                        session,
                        MsgType.ERROR,
                        session.local_seq,
                        0,
                        b"SHA256 mismatch",
                        outbound=True,
                    )
                    err = Packet(MsgType.ERROR, session.session_id, session.local_seq, 0, err_payload)
                    send_packet(sock, addr, err)
                    _security_log("SHA-256 verification failed (digest mismatch)", ok=False)
                    raise RDTError("SHA256 mismatch")

                if out is None:
                    # Valid zero-byte file transfer: create file only on successful FIN validation.
                    os.makedirs(os.path.dirname(destination_path) or ".", exist_ok=True)
                    out = open(destination_path, "wb")

                _security_log("SHA-256 verification passed")
                fin_ack = Packet(MsgType.FIN_ACK, session.session_id, session.local_seq, pkt.seq, b"")
                send_packet(sock, addr, fin_ack)
                session.remote_seq = pkt.seq
                return got_total

            elif pkt.msg_type == MsgType.ERROR:
                err_payload = _decrypt_payload(session, MsgType.ERROR, pkt.seq, pkt.ack, pkt.payload, outbound=False)
                raise RDTError(err_payload.decode("utf-8", errors="replace"))

            else:
                err_payload = _encrypt_payload(
                    session,
                    MsgType.ERROR,
                    session.local_seq,
                    0,
                    b"Unexpected packet type",
                    outbound=True,
                )
                err = Packet(MsgType.ERROR, session.session_id, 0, 0, err_payload)
                send_packet(sock, addr, err)
    finally:
        if out is not None:
            out.close()
