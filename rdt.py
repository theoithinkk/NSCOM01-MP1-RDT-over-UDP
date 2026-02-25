"""
Reliable Data Transfer (RDT) layer for a UDP-based file transfer protocol.

This module provides:
- Session state tracking (sequence numbers, chunk sizing, security key)
- Stop-and-wait reliability (retransmissions + ACK validation)
- Integrity checks:
  - CRC32 at the packet layer (Packet.decode)
  - End-to-end SHA-256 verification (FIN metadata)
- Optional secure mode:
  - PSK-based handshake authentication (HMAC-SHA256 proofs)
  - Per-session key derivation (HMAC-SHA256)
  - Optional AEAD payload protection (ChaCha20-Poly1305)
- Test hooks for ACK drop/delay to simulate network loss/latency

NOTES:
- CRC32 verification happens before payload processing.
- If secure mode is active, payloads are additionally authenticated/encrypted by AEAD.
"""

import hashlib
import hmac
import os
import random
import socket
import struct
import time
import ctypes
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
TEST_DELAY_MS = 0
ENCRYPTION_ENABLED = True

ANSI_RESET = "\x1b[0m"
ANSI_DIM = "\x1b[2m"
ANSI_BOLD = "\x1b[1m"
ANSI_RED = "\x1b[91m"
ANSI_GREEN = "\x1b[92m"
ANSI_YELLOW = "\x1b[93m"
ANSI_BLUE = "\x1b[94m"
ANSI_MAGENTA = "\x1b[95m"
ANSI_CYAN = "\x1b[96m"
ANSI_WHITE = "\x1b[97m"
LOG_LINE = "=" * 44


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        new_mode = mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(handle, new_mode) == 0:
            return False
        return True
    except Exception:
        return False


if COLOR_ENABLED:
    COLOR_ENABLED = _enable_windows_ansi()


# Stores per-session state shared by send/receive logic
@dataclass
class Session:
    session_id: int
    local_seq: int
    remote_seq: int
    chunk_size: int
    is_client: bool
    secure_key: Optional[bytes] = None


# Defines the base protocol-level exception used across RDT operations
class RDTError(Exception):
    pass


# Applies optional ANSI styles when terminal coloring is enabled
def _paint(text: str, *styles: str) -> str:
    if not COLOR_ENABLED or not styles:
        return text
    return "".join(styles) + text + ANSI_RESET


# Maps message types to display colors for wire tracing
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


# Emits verbose trace logs for debugging internal flow
def _trace(verbose: bool, message: str) -> None:
    if verbose:
        print(_paint(f"[rdt] {message}", ANSI_DIM, ANSI_CYAN))


# Emits security-related pass/fail logs
def _security_log(message: str, ok: bool = True) -> None:
    color = ANSI_GREEN if ok else ANSI_RED
    print(_paint(f"[SECURITY] {message}", ANSI_BOLD, color))


# Emits high-visibility retransmission logs
def _retransmit_log(message: str) -> None:
    print(_paint(f"[RETRANSMIT] {message}", ANSI_BOLD, ANSI_YELLOW))


# Prints a section divider for easier scanning of grouped logs
def _section(title: str) -> None:
    print()
    print(_paint(f"=== {title} ===", ANSI_BLUE))


# Ensures cryptography dependency exists before enabling secure mode
def _require_crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401
    except Exception as exc:
        raise RDTError(
            "Secure mode requires 'cryptography'. Install with: py -3 -m pip install cryptography"
        ) from exc


# Configures optional PSK used for secure handshake and key derivation
def configure_security(psk: Optional[str]) -> None:
    global SECURE_PSK_BYTES
    if psk:
        if ENCRYPTION_ENABLED:
            _require_crypto()
        SECURE_PSK_BYTES = psk.encode("utf-8")
    else:
        SECURE_PSK_BYTES = None


# Reports whether secure mode is currently enabled
def security_enabled() -> bool:
    return SECURE_PSK_BYTES is not None


# Configures whether AEAD payload encryption is enabled
def configure_encryption(enabled: bool) -> None:
    global ENCRYPTION_ENABLED
    ENCRYPTION_ENABLED = enabled
    if ENCRYPTION_ENABLED and SECURE_PSK_BYTES is not None:
        _require_crypto()


# Reports whether payload encryption is currently enabled
def encryption_enabled() -> bool:
    return ENCRYPTION_ENABLED


# Configures test hook probability for dropping outbound ACKs
def configure_test_drop_ack(rate: float) -> None:
    global TEST_DROP_ACK_RATE
    TEST_DROP_ACK_RATE = max(0.0, min(1.0, rate))


# Configures test hook delay (milliseconds) for outbound ACKs while receiving DATA
def configure_test_delay_ms(delay_ms: int) -> None:
    global TEST_DELAY_MS
    TEST_DELAY_MS = max(0, int(delay_ms))


# Enables wire tracing and prints one-time security mode summary
def set_wire_trace(enabled: bool, role: str = "APP") -> None:
    global WIRE_TRACE_ENABLED, WIRE_TRACE_ROLE, SECURITY_STATUS_PRINTED
    WIRE_TRACE_ENABLED = enabled
    WIRE_TRACE_ROLE = role.upper()
    if enabled:
        print()
        print(_paint(f"=== File Transfer Protocol ({WIRE_TRACE_ROLE}) ===", ANSI_CYAN))
        print(
            _paint(
                f"[RUNTIME] timeout={TIMEOUT_SECONDS:.2f}s max_retries={MAX_RETRIES} "
                f"max_payload={MAX_PAYLOAD} ack_drop_rate={TEST_DROP_ACK_RATE:.2f} ack_delay_ms={TEST_DELAY_MS}",
                ANSI_WHITE,
            )
        )
        print(_paint(LOG_LINE, ANSI_DIM))
    if enabled and not SECURITY_STATUS_PRINTED:
        if security_enabled():
            if encryption_enabled():
                mode_text = "integrity=crc32+sha256+aead, encryption=enabled, authentication=psk-hmac"
            else:
                mode_text = "integrity=crc32+sha256, encryption=disabled, authentication=psk-hmac"
            print(
                _paint(
                    f"[SECURITY] {mode_text}",
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


# Builds a compact trace string for sent packets
def _format_sent_packet(packet: Packet) -> str:
    return (
        f"[Type={_paint(packet.msg_type.name, _msg_style(packet.msg_type))}, "
        f"SeqNum={packet.seq}, AckNum={packet.ack}, SessionID={packet.session_id}, "
        f"PayloadLen={len(packet.payload)}]"
    )


# Builds a compact trace string for received packets
def _format_received_packet(packet: Packet) -> str:
    return (
        f"[Type={_paint(packet.msg_type.name, _msg_style(packet.msg_type))}, "
        f"SeqNum={packet.seq}, AckNum={packet.ack}, SessionID={packet.session_id}, "
        f"PayloadLen={len(packet.payload)}]"
    )


# Prints key session parameters after handshake for easier verification
def log_session_parameters(session: Session, peer_addr: Tuple[str, int]) -> None:
    mode = "secure" if session.secure_key else "plain"
    _section("Session Parameters")
    print(_paint(f"SessionID   = {session.session_id}", ANSI_GREEN))
    print(_paint(f"Peer        = {peer_addr}", ANSI_GREEN))
    print(_paint(f"LocalSeq    = {session.local_seq}", ANSI_GREEN))
    print(_paint(f"RemoteSeq   = {session.remote_seq}", ANSI_GREEN))
    print(_paint(f"ChunkSize   = {session.chunk_size}", ANSI_GREEN))
    print(_paint(f"Mode        = {mode}", ANSI_GREEN))
    print(_paint(f"Timeout     = {TIMEOUT_SECONDS:.2f}s", ANSI_GREEN))
    print(_paint(f"MaxRetries  = {MAX_RETRIES}", ANSI_GREEN))


# Prints phase markers to visually separate operation sequences
def log_phase(title: str) -> None:
    _section(title)


# Parses semicolon-delimited key=value payload strings
def _parse_kv_payload(payload: bytes) -> Dict[str, str]:
    text = payload.decode("utf-8", errors="ignore").strip()
    out: Dict[str, str] = {}
    for part in text.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


# Derives per-session AEAD key from PSK + nonces + session id
def _derive_session_key(psk: bytes, cnonce: bytes, snonce: bytes, session_id: int) -> bytes:
    # HKDF-like derivation via HMAC-SHA256 for a single 32-byte key.
    salt = cnonce + snonce + struct.pack("!I", session_id)
    return hmac.new(psk, b"rdt-session-key|" + salt, hashlib.sha256).digest()


# Builds server handshake proof using HMAC-SHA256 over transcript fields
def _server_proof(psk: bytes, cnonce: bytes, snonce: bytes, client_isn: int, server_isn: int, session_id: int) -> str:
    material = b"server-proof|" + cnonce + snonce + struct.pack("!III", client_isn, server_isn, session_id)
    return hmac.new(psk, material, hashlib.sha256).hexdigest()


# Builds client handshake proof using HMAC-SHA256 over transcript fields
def _client_proof(psk: bytes, cnonce: bytes, snonce: bytes, client_isn: int, server_isn: int, session_id: int) -> str:
    material = b"client-proof|" + cnonce + snonce + struct.pack("!III", client_isn, server_isn, session_id)
    return hmac.new(psk, material, hashlib.sha256).hexdigest()


# Constructs a deterministic 12-byte nonce from session/direction/sequence
def _nonce(session_id: int, seq: int, from_client: bool) -> bytes:
    # 12-byte nonce: session_id(4) + dir(1) + seq(4) + pad(3)
    direction = b"\x01" if from_client else b"\x00"
    return struct.pack("!I", session_id) + direction + struct.pack("!I", seq) + b"\x00\x00\x00"


# Builds AEAD additional authenticated data from packet metadata
def _aad(msg_type: MsgType, session_id: int, seq: int, ack: int) -> bytes:
    return struct.pack("!BIII", int(msg_type), session_id, seq, ack)


# Encrypts payload with AEAD when secure mode is active
def _encrypt_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool) -> bytes:
    if not session.secure_key or not ENCRYPTION_ENABLED:
        return payload
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from_client = session.is_client if outbound else (not session.is_client)
    cipher = ChaCha20Poly1305(session.secure_key)
    ciphertext = cipher.encrypt(_nonce(session.session_id, seq, from_client), payload, _aad(msg_type, session.session_id, seq, ack))
    return ciphertext


# Decrypts and authenticates payload with AEAD when secure mode is active
def _decrypt_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool) -> bytes:
    if not session.secure_key or not ENCRYPTION_ENABLED:
        return payload
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from_client = session.is_client if outbound else (not session.is_client)
    cipher = ChaCha20Poly1305(session.secure_key)
    try:
        return cipher.decrypt(_nonce(session.session_id, seq, from_client), payload, _aad(msg_type, session.session_id, seq, ack))
    except Exception as exc:
        raise RDTError("AEAD authentication failed") from exc


# Encodes FIN metadata carrying total size and final SHA-256 digest
def _build_fin_payload(total_size: int, digest_hex: str) -> bytes:
    return f"EOF|size={total_size}|sha256={digest_hex}".encode("utf-8")


# Parses FIN metadata payload into expected size and hash
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


# Identifies Windows UDP reset errors that should be treated as transient
def _is_connection_reset_error(exc: BaseException) -> bool:
    if isinstance(exc, ConnectionResetError):
        return True
    if not isinstance(exc, OSError):
        return False
    return getattr(exc, "winerror", None) == 10054


# Receives and decodes one packet with optional timeout and CRC validation
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
            f"[{WIRE_TRACE_ROLE}][RECV] from={addr}, {_format_received_packet(packet)}"
        )
        print(
            _paint(
                f"[INTEGRITY] CRC32 verified: Type={packet.msg_type.name}, "
                f"SeqNum={packet.seq}, SessionID={packet.session_id}",
                ANSI_GREEN,
            )
        )
    return packet, addr


# Encodes and sends one packet to a peer address
def send_packet(sock: socket.socket, addr: Tuple[str, int], packet: Packet) -> None:
    if WIRE_TRACE_ENABLED:
        print(f"[{WIRE_TRACE_ROLE}][SEND] to={addr}, {_format_sent_packet(packet)}")
    sock.sendto(packet.encode(), addr)


# Encrypts payload based on current session settings
def protect_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool = True) -> bytes:
    return _encrypt_payload(session, msg_type, seq, ack, payload, outbound=outbound)


# Decrypts payload based on current session settings
def unprotect_payload(session: Session, msg_type: MsgType, seq: int, ack: int, payload: bytes, outbound: bool = False) -> bytes:
    return _decrypt_payload(session, msg_type, seq, ack, payload, outbound=outbound)


# Waits for a matching ACK packet or raises protocol/timeout errors
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


# Sends a packet with stop-and-wait retransmission until ACK or retry limit
def send_with_retransmit(
    sock: socket.socket,
    addr: Tuple[str, int],
    packet: Packet,
    expect_ack_for: int,
    verbose: bool = False,
) -> None:
    last_error = "Timeout"
    if WIRE_TRACE_ENABLED:
        log_phase(f"Reliable Send Sequence: Type={packet.msg_type.name} SeqNum={packet.seq}")
    for attempt in range(1, MAX_RETRIES + 1):
        if attempt > 1:
            _retransmit_log(
                f"retry Type={packet.msg_type.name} SeqNum={packet.seq} Attempt={attempt}/{MAX_RETRIES}"
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
                    f"recovered Type={packet.msg_type.name} SeqNum={packet.seq} "
                    f"on Attempt={attempt}/{MAX_RETRIES}"
                )
            return
        except (socket.timeout, TimeoutError):
            last_error = "Timeout waiting for ACK"
            _trace(verbose, f"timeout waiting ACK for seq={expect_ack_for}")
            _retransmit_log(f"timeout waiting ACK for SeqNum={expect_ack_for}")
        except RDTError as exc:
            last_error = str(exc)
            _trace(verbose, f"retransmit reason: {last_error}")
            _retransmit_log(f"retry reason for SeqNum={expect_ack_for}: {last_error}")
    raise TimeoutError(f"Retransmission failed: {last_error}")


# Runs client-side 3-way handshake plus optional secure proof verification
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


# Runs server-side handshake loop that validates mode and optional client proof
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


# Sends file chunks reliably then finalizes with FIN metadata and FIN-ACK wait
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


# Receives file chunks in order, ACKs each, and verifies final FIN hash/size
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
                        if TEST_DELAY_MS > 0:
                            _trace(verbose, f"test hook delayed ACK for seq={pkt.seq} by {TEST_DELAY_MS}ms")
                            time.sleep(TEST_DELAY_MS / 1000.0)
                        send_packet(sock, addr, ack)
                    expected_seq += 1
                else:
                    last_ok = expected_seq - 1
                    ack = Packet(MsgType.ACK, session.session_id, session.local_seq, last_ok, b"")
                    if TEST_DROP_ACK_RATE > 0.0 and random.random() < TEST_DROP_ACK_RATE:
                        _trace(verbose, f"test hook dropped duplicate ACK for seq={last_ok}")
                    else:
                        if TEST_DELAY_MS > 0:
                            _trace(verbose, f"test hook delayed duplicate ACK for seq={last_ok} by {TEST_DELAY_MS}ms")
                            time.sleep(TEST_DELAY_MS / 1000.0)
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
