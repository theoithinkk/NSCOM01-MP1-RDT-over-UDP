# Mini RFC: Reliable Data Transfer over UDP (RDT-UDP)

## a. Introduction
This document specifies a custom application-layer protocol that provides reliable, ordered file transfer on top of UDP.  
The implementation supports:
- session establishment
- per-chunk reliability (ACK + retransmission)
- explicit end-of-transfer signaling
- integrity verification (CRC32 per datagram, SHA-256 end-to-end file hash)
- optional secure mode (PSK-authenticated handshake + AEAD encrypted payloads)

Implementation language: Python  
Transport: UDP sockets only  
Interface: command line (direct scripts and interactive launcher)

## b. Protocol Overview
The protocol supports two operations:
- `GET <filename>`: download from server to client
- `PUT <filename>`: upload from client to server

Core message flow:
- `SYN`, `SYN-ACK`, `ACK` for session setup
- `REQ` for operation request
- `DATA` + `ACK` for reliable transfer
- `FIN` + `FIN-ACK` for clean close
- `ERROR` for protocol/validation failures

### b.i Swimlane Diagrams and Message Exchange
Download (`GET`)
```text
Client                                           Server
  |--- SYN(chunk, secure?, cnonce?) ------------->|
  |<-- SYN-ACK(session, server_isn, proof?) ------|
  |--- ACK(client_proof?) ------------------------>|
  |--- REQ("GET file") --------------------------->|
  |<-- DATA(seq=n) --------------------------------|
  |--- ACK(ack=n) -------------------------------->|
  |<-- DATA(seq=n+1) ------------------------------|
  |--- ACK(ack=n+1) ------------------------------>|
  |<-- FIN(size, sha256) --------------------------|
  |--- FIN-ACK ----------------------------------->|
```

Upload (`PUT`)
```text
Client                                           Server
  |--- SYN(chunk, secure?, cnonce?) ------------->|
  |<-- SYN-ACK(session, server_isn, proof?) ------|
  |--- ACK(client_proof?) ------------------------>|
  |--- REQ("PUT file") --------------------------->|
  |--- DATA(seq=n) -------------------------------->|
  |<-- ACK(ack=n) ---------------------------------|
  |--- DATA(seq=n+1) ------------------------------>|
  |<-- ACK(ack=n+1) -------------------------------|
  |--- FIN(size, sha256) ------------------------->|
  |<-- FIN-ACK ------------------------------------|
```

Notes:
- Secure-mode fields (`cnonce`, proofs) are present only when `--secure-psk` is enabled.
- In secure mode, payloads of `REQ/DATA/FIN/ERROR` are AEAD-protected.

## c. Packet Message Formats
Each UDP datagram uses network byte order (`big-endian`) header:
- `msg_type` (1 byte)
- `session_id` (4 bytes)
- `seq` (4 bytes)
- `ack` (4 bytes)
- `payload_len` (2 bytes)
- `checksum` (4 bytes, CRC32)
- `payload` (`payload_len` bytes, max 1024)

Header struct format: `!BIIIHI`

### c.i Message Types
- `1 = SYN`
- `2 = SYN_ACK`
- `3 = DATA`
- `4 = ACK`
- `5 = FIN`
- `6 = FIN_ACK`
- `7 = ERROR`
- `8 = REQ`

## d. State Machines (Transition Diagram)

### d.i Client
```text
CLOSED
  -> send SYN -> SYN_SENT
SYN_SENT
  -> recv valid SYN-ACK, send ACK -> ESTABLISHED
ESTABLISHED
  -> send REQ(GET|PUT) -> TRANSFERRING
TRANSFERRING
  -> DATA/ACK loop (send or receive depending on op)
  -> FIN exchange -> CLOSED
```

### d.ii Server
```text
LISTEN
  -> recv SYN, send SYN-ACK
  -> recv valid ACK -> ESTABLISHED
ESTABLISHED
  -> recv REQ(GET|PUT) -> TRANSFERRING
TRANSFERRING
  -> DATA/ACK loop (send for GET, receive for PUT)
  -> FIN exchange
  -> return LISTEN for next session
```

## e. Reliability Mechanisms
- Per-chunk sequencing via `seq`.
- Per-chunk acknowledgement via `ACK.ack = DATA.seq`.
- Timeout/retransmission with bounded retries.
- Ordered delivery:
  - receiver accepts only expected `seq`
  - out-of-order packets trigger re-ACK of last valid sequence.
- Session binding:
  - strict peer address checks (`ip,port`)
  - strict `session_id` checks.
- Datagram integrity:
  - CRC32 in packet header validated at decode.
- End-to-end file integrity:
  - SHA-256 over file data verified at `FIN`.

## f. Error-handling
Detected and handled conditions include:
- timeout waiting for expected packet/ACK
- file not found on server during `GET`
- session mismatch (`session_id` invalid)
- unexpected packet type for current state
- checksum mismatch (packet dropped)
- secure-mode authentication failure (handshake rejected)
- AEAD authentication failure (payload tamper/decrypt failure)
- SHA-256/file size mismatch at end of transfer

Protocol response strategy:
- retransmit on timeout where applicable
- send `ERROR` packets for protocol violations
- abort session on unrecoverable errors.

## g. File Transfer Operations
- Binary-safe read/write (`rb`/`wb`).
- `GET`:
  - server reads stored file, sends chunks reliably to client
  - client writes local destination path.
- `PUT`:
  - client reads local file, sends chunks reliably to server
  - server stores file in configured storage directory.
- Filename safety:
  - server stores using basename to avoid path traversal.

Secure mode behavior:
- Handshake is PSK-authenticated.
- `REQ`, `DATA`, `FIN`, `ERROR` payloads are encrypted/authenticated.
- ACK control packets remain unencrypted payload-empty control packets.

## h. End-of-File Signaling
EOF is explicit:
- sender transmits `FIN` after all `DATA`.
- receiver verifies end-to-end SHA-256 and size from FIN payload metadata.
- if valid: receiver replies `FIN-ACK`.
- if invalid: receiver sends `ERROR` and does not accept transfer.

---

## RFCs and Standards Referenced
The implementation is a custom protocol, but uses concepts inspired by:

- `RFC 768` (UDP): transport substrate.
- `RFC 9293` (TCP): handshake/session/ack/fin design inspiration.
- `RFC 1350` (TFTP): lockstep file-transfer-over-UDP style.
- `RFC 1952 Appendix` / standard CRC32 polynomial practice: packet error detection concept.
- `RFC 2104` (HMAC): PSK proof construction in secure handshake.
- `RFC 8439` (ChaCha20-Poly1305): AEAD encryption/authentication in secure mode.
- `RFC 5869` (HKDF): key-derivation design reference (implementation uses HMAC-based derivation in same spirit).

Note: this protocol is educational and not a replacement for DTLS/QUIC/TLS in production systems.
