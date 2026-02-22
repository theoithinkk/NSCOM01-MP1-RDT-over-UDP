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
Download:
1. Client -> Server: `SYN(chunk_size)`
2. Server -> Client: `SYN-ACK(session_id, server_isn)`
3. Client -> Server: `ACK`
4. Client -> Server: `REQ(GET filename)`
5. Server -> Client: `DATA(seq=n)` (repeated)
6. Client -> Server: `ACK(ack=n)` (per chunk)
7. Server -> Client: `FIN(seq=last+1)`
8. Client -> Server: `FIN-ACK(ack=FIN.seq)`

Upload:
1. Client -> Server: `SYN(chunk_size)`
2. Server -> Client: `SYN-ACK(session_id, server_isn)`
3. Client -> Server: `ACK`
4. Client -> Server: `REQ(PUT filename)`
5. Client -> Server: `DATA(seq=n)` (repeated)
6. Server -> Client: `ACK(ack=n)` (per chunk)
7. Client -> Server: `FIN(seq=last+1)`
8. Server -> Client: `FIN-ACK(ack=FIN.seq)`

## 3. Packet Message Format
Each UDP datagram uses this binary layout (network byte order):

- `msg_type` (1 byte)
- `session_id` (4 bytes)
- `seq` (4 bytes)
- `ack` (4 bytes)
- `payload_len` (2 bytes)
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

## 9. Usage
Interactive one-file launcher:
```bash
python app.py
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

Download:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op get --remote-file sample.bin --local-file downloads/sample.bin
```

Upload:
```bash
python client.py --server-host 127.0.0.1 --server-port 9000 --op put --remote-file upload.bin --local-file ./upload.bin
```
