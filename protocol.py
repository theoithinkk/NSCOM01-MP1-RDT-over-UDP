"""
Protocol definitions for the Reliable UDP File Transfer system.

This module defines:
- Message type identifiers exchanged between client and server.
- The Packet data model used on the wire.
- Encoding/decoding helpers with CRC32 integrity protection.
"""

import enum
import struct
import zlib
from dataclasses import dataclass


MAX_PAYLOAD = 1024
HEADER_FMT = "!BIIIHI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


class MsgType(enum.IntEnum):
    """Enumeration of message types exchanged over UDP."""

    SYN = 1
    SYN_ACK = 2
    DATA = 3
    ACK = 4
    FIN = 5
    FIN_ACK = 6
    ERROR = 7
    REQ = 8


@dataclass
class Packet:
    """Represents a protocol packet transmitted over UDP.

    Fields:
        msg_type: Type of protocol message.
        session_id: Unique session identifier.
        seq: Sequence number.
        ack: Acknowledgment number.
        payload: Optional payload bytes.

    The packet is serialized using a fixed header format followed
    by payload data. Integrity is protected using CRC32.
    """

    msg_type: MsgType
    session_id: int
    seq: int
    ack: int
    payload: bytes = b""

    def encode(self) -> bytes:
        """Serialize the packet into wire format and append CRC32 checksum.

        Returns:
            bytes: Encoded packet ready for UDP transmission.

        Raises:
            ValueError: If payload exceeds MAX_PAYLOAD.
        """
        payload_len = len(self.payload)
        if payload_len > MAX_PAYLOAD:
            raise ValueError(f"Payload too large: {payload_len} > {MAX_PAYLOAD}")

        # Build header with checksum field set to zero for CRC calculation.
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

    @staticmethod
    def decode(datagram: bytes) -> "Packet":
        """Parse wire bytes into a Packet and verify integrity.

        Performs:
        - Header extraction
        - Payload length validation
        - CRC32 checksum verification

        Args:
            datagram: Raw UDP datagram bytes.

        Returns:
            Packet: Decoded and validated packet.

        Raises:
            ValueError: If header is invalid, payload length mismatches,
                        or checksum verification fails.
        """
        if len(datagram) < HEADER_SIZE:
            raise ValueError("Datagram too small for header")

        msg_raw, session_id, seq, ack, payload_len, checksum = struct.unpack(
            HEADER_FMT, datagram[:HEADER_SIZE]
        )

        payload = datagram[HEADER_SIZE:]

        if payload_len != len(payload):
            raise ValueError("Payload length mismatch")

        # Recompute checksum with checksum field zeroed.
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


def build_error(session_id: int, seq: int, message: str) -> Packet:
    """Create a standard ERROR packet with UTF-8 encoded message payload.

    Args:
        session_id: Active session identifier.
        seq: Sequence number for the error packet.
        message: Human-readable error message.

    Returns:
        Packet: ERROR packet ready for transmission.
    """
    return Packet(MsgType.ERROR,session_id,seq,0,message.encode("utf-8", errors="replace"),
    )