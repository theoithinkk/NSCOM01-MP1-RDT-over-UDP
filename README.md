# Reliable Data Transfer over UDP (NSCOM01 MP1)

## 1. Introduction
This project implements a custom application-layer protocol that provides reliability, ordered transfer, and session management on top of UDP for file upload and download.

Implementation language: Python  
Interface: command line  
Transport: UDP sockets only

## 2. Protocol Overview
The protocol provides:
- Session establishment (`SYN`, `SYN-ACK`, `ACK`)
- Reliable chunk transfer (`DATA` + `ACK`, timeout + retransmission)
- Clean end-of-file signaling (`FIN`, `FIN-ACK`)
- Error signaling (`ERROR`)
- File operation request (`REQ`)

Supported operations:
- `GET <filename>`: client downloads file from server
- `PUT <filename>`: client uploads file to server

### 2.1 Message Exchange (Swimlane Style)
Assume secure mode (`--secure-psk`) is enabled.  
All packets include header CRC32.  
After handshake, payloads of `REQ`, `DATA`, `FIN`, and `ERROR` are AEAD-protected.

Handshake lane:
1. Client -> Server: `SYN`
   - `session_id=0`, `seq=client_isn`, `ack=0`
   - Payload: `chunk=<N>;secure=1;cnonce=<client_nonce_hex>`
2. Server -> Client: `SYN-ACK`
   - `session_id=<sid>`, `seq=server_isn`, `ack=client_isn`
   - Payload: `chunk=<N>;snonce=<server_nonce_hex>;sproof=<hmac_hex>`
   - Server computes `sproof` with PSK HMAC.
3. Client verifies `sproof`, derives session key, then Client -> Server: `ACK`
   - `session_id=<sid>`, `seq=client_isn+1`, `ack=server_isn`
   - Payload: `cproof=<hmac_hex>`
4. Server verifies `cproof` and derives the same session key.

GET lane (client downloads):
1. Client -> Server: `REQ`
   - `session_id=<sid>`, `seq=client_isn+1`, `ack=0`
   - Payload (AEAD): `GET <filename>`
2. Server -> Client: `DATA(seq=n)` repeated for each chunk
   - Payload (AEAD): chunk bytes
   - Sender updates running SHA-256 on plaintext chunk before encrypting.
3. Client -> Server: `ACK`
   - `ack=n` for each valid `DATA` received
   - If out-of-order, client re-ACKs last valid sequence.
4. Server -> Client: `FIN`
   - `seq=last_data_seq+1`
   - Payload (AEAD): `EOF|size=<total_bytes>|sha256=<digest_hex>`
5. Client validates total size and SHA-256, then Client -> Server: `FIN-ACK`
   - `ack=FIN.seq`
   - If validation fails, client sends `ERROR` instead.

PUT lane (client uploads):
1. Client -> Server: `REQ`
   - `session_id=<sid>`, `seq=client_isn+1`, `ack=0`
   - Payload (AEAD): `PUT <filename>`
2. Client -> Server: `DATA(seq=n)` repeated for each chunk
   - Payload (AEAD): chunk bytes
   - Sender updates running SHA-256 on plaintext chunk before encrypting.
3. Server -> Client: `ACK`
   - `ack=n` for each valid `DATA` received
   - If out-of-order, server re-ACKs last valid sequence.
4. Client -> Server: `FIN`
   - `seq=last_data_seq+1`
   - Payload (AEAD): `EOF|size=<total_bytes>|sha256=<digest_hex>`
5. Server validates total size and SHA-256, then Server -> Client: `FIN-ACK`
   - `ack=FIN.seq`
   - If validation fails, server sends `ERROR` instead.

## 3. Packet Message Format
Each UDP datagram uses this binary layout (network byte order):

- `msg_type` (1 byte)
- `session_id` (4 bytes)
- `seq` (4 bytes)
- `ack` (4 bytes)
- `payload_len` (2 bytes)
- `checksum` (4 bytes, CRC32)
- `payload` (`payload_len` bytes, max 1024)

### 3.1 Message Types
- `1 = SYN`
- `2 = SYN_ACK`
- `3 = DATA`
- `4 = ACK`
- `5 = FIN`
- `6 = FIN_ACK`
- `7 = ERROR`
- `8 = REQ`

## 4. State Machines
### 4.1 Client
1. `CLOSED` -> send `SYN` -> `SYN_SENT`
2. `SYN_SENT` -> receive `SYN-ACK` + send `ACK` -> `ESTABLISHED`
3. `ESTABLISHED` -> send `REQ(GET|PUT)` -> `TRANSFERRING`
4. `TRANSFERRING` -> exchange `DATA/ACK` -> `WAIT_FIN`
5. `WAIT_FIN` -> receive/send `FIN` and return `FIN-ACK` -> `CLOSED`

### 4.2 Server
1. `LISTEN` -> receive `SYN` -> send `SYN-ACK`
2. receive `ACK` -> `ESTABLISHED`
3. receive `REQ(GET|PUT)` -> `TRANSFERRING`
4. exchange `DATA/ACK`
5. send/receive `FIN` -> return `FIN-ACK` -> `LISTEN`

## 5. Reliability Mechanisms
- Sequence numbers per data chunk.
- Per-chunk acknowledgements (`ACK.ack = DATA.seq`).
- Timeout-based retransmission with bounded retries.
- Ordered delivery by accepting only expected sequence and re-ACKing last valid sequence for out-of-order packets.
- Datagram integrity check using CRC32 checksum in packet header.
- End-to-end file integrity check using SHA-256 (verified at `FIN`).

## 6. Error Handling
Implemented checks and responses:
- Timeout: retry and eventually abort session.
- File not found (`GET`): server sends `ERROR` message.
- Session mismatch: receiver sends `ERROR` and ignores invalid packet.
- Unexpected packet type: receiver sends `ERROR`.

## 7. File Transfer Operations
- Binary-safe transfer (`rb`/`wb` mode).
- Download stores server file to local path.
- Upload stores client file under server storage directory.

## 8. End-of-File Signaling
End of transfer is explicit:
- sender transmits `FIN` after all data chunks
- receiver confirms with `FIN-ACK`

## 9. Security and Integrity Details
### 9.1 Checksum (CRC32)
- Purpose: detect accidental corruption per UDP datagram.
- Where implemented:
  - `protocol.py` -> `Packet.encode()` computes checksum.
  - `protocol.py` -> `Packet.decode()` verifies checksum.
- How used:
  - Sender computes CRC32 over header(with checksum=0) + payload.
  - Receiver recomputes and compares.
  - Mismatch raises decode error and packet is dropped.

### 9.2 File Hashing (SHA-256)
- Purpose: verify end-to-end integrity of the full reconstructed file.
- Where implemented:
  - `rdt.py` -> `send_file()` computes SHA-256 while sending chunks.
  - `rdt.py` -> `recv_file()` computes SHA-256 while receiving chunks.
- How used:
  - Sender places `size` and `sha256` metadata in `FIN` payload.
  - Receiver checks expected size/hash at `FIN`.
  - If mismatch: receiver sends `ERROR` and does not send `FIN-ACK`.

### 9.3 Authentication (PSK + HMAC Proofs)
- Purpose: prove both peers know the same shared secret before transfer.
- Where implemented:
  - `rdt.py` -> `configure_security()`, `client_handshake()`, `server_handshake()`.
- How used:
  - Enabled by `--secure-psk`.
  - Client sends nonce in `SYN`.
  - Server returns nonce + HMAC proof in `SYN-ACK`.
  - Client verifies server proof, sends client proof in final `ACK`.
  - Server verifies client proof.
  - Session proceeds only if both proofs are valid.

### 9.4 Encryption (ChaCha20-Poly1305 AEAD)
- Purpose: provide confidentiality and tamper detection for payload data.
- Where implemented:
  - `rdt.py` -> internal `_encrypt_payload()` / `_decrypt_payload()`
  - `rdt.py` -> `protect_payload()` / `unprotect_payload()`
- How used:
  - Enabled by `--secure-psk` (same PSK on both peers).
  - Applies to payloads of `REQ`, `DATA`, `FIN`, and `ERROR`.
  - `ACK`/`FIN-ACK` control packets remain payload-empty.
  - If auth/decrypt check fails, transfer is aborted with error.

## 10. Usage
Interactive one-file launcher:
```bash
python app.py
```

Enable detailed handshake/session/data logs:
```bash
python app.py --verbose
```
Verbose mode also prints per-packet wire traces for all message types (`SYN`, `SYN-ACK`, `ACK`, `REQ`, `DATA`, `FIN`, `FIN-ACK`, `ERROR`).

Enable authenticated + encrypted mode (both peers must use same PSK):
```bash
python app.py --secure-psk "your-shared-secret"
```

You will be prompted to choose:
- mode (`server` or `client`)
- host/port
- storage directory (server mode)
- operation (`get`/`put`) and file paths (client mode)
- chunk size (client mode)

Legacy direct commands are still available:

Start server:
```bash
python server.py --host 0.0.0.0 --port 9000 --storage server_storage
```
Verbose:
```bash
python server.py --host 0.0.0.0 --port 9000 --storage server_storage --verbose
```
Secure:
```bash
python server.py --host 0.0.0.0 --port 9000 --storage server_storage --secure-psk "your-shared-secret"
```

Download:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op get --remote-file sample.bin --local-file downloads/sample.bin
```
Verbose:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op get --remote-file sample.bin --local-file downloads/sample.bin --verbose
```
Secure:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op get --remote-file sample.bin --local-file downloads/sample.bin --secure-psk "your-shared-secret"
```

Upload:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op put --remote-file upload.bin --local-file ./upload.bin
```
Verbose:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op put --remote-file upload.bin --local-file ./upload.bin --verbose
```
Secure:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op put --remote-file upload.bin --local-file ./upload.bin --secure-psk "your-shared-secret"
```

### 10.1 Secure Mode Notes
- Install dependency once:
```bash
py -3 -m pip install cryptography
```
- Security in secure mode:
  - Handshake authentication: HMAC-based PSK proof exchange.
  - Payload encryption/authentication: ChaCha20-Poly1305 AEAD.
  - Packet checksum: CRC32 still applied at transport packet level.
  - End-to-end file hash: SHA-256 verification at `FIN`.
