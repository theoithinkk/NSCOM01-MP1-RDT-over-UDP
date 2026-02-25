import enum
import struct
import zlib
from dataclasses import dataclass
from typing import Tuple


MAX_PAYLOAD = 1024
HEADER_FMT = "!BIIIHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


# Defines message type identifiers exchanged over UDP
class MsgType(enum.IntEnum):
    SYN = 1
    SYN_ACK = 2
    DATA = 3
    ACK = 4
    FIN = 5
    FIN_ACK = 6
    ERROR = 7
    REQ = 8


# Defines the packet model with encode/decode helpers and CRC32 protection
@dataclass
class Packet:
    msg_type: MsgType
    session_id: int
    seq: int
    ack: int
    payload: bytes = b""

    # Serializes a Packet into wire format and appends CRC32
    def encode(self) -> bytes:
        payload_len = len(self.payload)
        if payload_len > MAX_PAYLOAD:
            raise ValueError(f"Payload too large: {payload_len} > {MAX_PAYLOAD}")
        header_wo_checksum = struct.pack(
            HEADER_FMT,
            int(self.msg_type),
            self.session_id,
            self.seq,
            self.ack,
            payload_len,
            0,
        )
        checksum = zlib.crc32(header_wo_checksum + self.payload) & 0xFFFFFFFF
        header = struct.pack(
            HEADER_FMT,
            int(self.msg_type),
            self.session_id,
            self.seq,
            self.ack,
            payload_len,
            checksum,
        )
        return header + self.payload

    # Parses wire bytes into a Packet and verifies CRC32/payload length
    @staticmethod
    def decode(datagram: bytes) -> "Packet":
        if len(datagram) < HEADER_SIZE:
            raise ValueError("Datagram too small for header")
        msg_raw, session_id, seq, ack, payload_len, checksum = struct.unpack(
            HEADER_FMT, datagram[:HEADER_SIZE]
        )
        payload = datagram[HEADER_SIZE:]
        if payload_len != len(payload):
            raise ValueError("Payload length mismatch")
        header_wo_checksum = struct.pack(
            HEADER_FMT,
            msg_raw,
            session_id,
            seq,
            ack,
            payload_len,
            0,
        )
        expected_checksum = zlib.crc32(header_wo_checksum + payload) & 0xFFFFFFFF
        if checksum != expected_checksum:
            raise ValueError("Checksum mismatch")
        return Packet(MsgType(msg_raw), session_id, seq, ack, payload)


# Encodes a structured ERROR payload as key/value text
def encode_error_payload(code: str, message: str) -> bytes:
    safe_code = (code or "UNKNOWN").strip().upper().replace(";", "_")
    safe_message = (message or "").strip().replace(";", ",")
    return f"code={safe_code};msg={safe_message}".encode("utf-8", errors="replace")


# Decodes structured ERROR payload text into (code, message)
def decode_error_payload(payload: bytes) -> Tuple[str, str]:
    text = payload.decode("utf-8", errors="replace").strip()
    if text.startswith("code=") and ";msg=" in text:
        code_part, msg_part = text.split(";msg=", 1)
        code = code_part.split("=", 1)[1].strip().upper() or "UNKNOWN"
        message = msg_part.strip()
        return code, message
    return "UNKNOWN", text


# Builds a standard ERROR packet with structured payload
def build_error(session_id: int, seq: int, message: str, code: str = "UNKNOWN") -> Packet:
    return Packet(MsgType.ERROR, session_id, seq, 0, encode_error_payload(code, message))
