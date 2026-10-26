# Project 2: "NexusTunnel" — Secure Transport Layer & Protocol Engineering

## Executive Summary
**NexusTunnel** is a dedicated security laboratory simulating authenticated channel establishment across transport and network layer protocols. It demonstrates the stateful mechanics of TLS/SSL handshakes, SSH-2.0 Diffie-Hellman session negotiations, and IPsec ESP encapsulation.

---

## Technical Specifications

1. **TLS/SSL Handshake Engine (Steps 1–5)**:
   - **Step 1: Client Hello**: Transmits 32-byte pseudo-random nonce and available cipher suites.
   - **Step 2: Server Hello & Certificate**: Server selects cipher suite, provides server random nonce, and presents X.509 certificate.
   - **Step 3: Client Key Exchange**: Client creates 48-byte Pre-Master Secret, encrypts with server's RSA public key.
   - **Step 4: PRF Key Derivation**: Derives Master Secret and 4 symmetric session keys (`client_write_key`, `server_write_key`, IVs) using HMAC-SHA256 PRF.
   - **Step 5: Finished Verification**: Mutual HMAC verification of complete transcript integrity.
   - **Encrypted Transmission**: Live payload transmission symmetrically encrypted via authenticated **AES-128-GCM**.

2. **SSH-2.0 Connection Simulator**:
   - Version negotiation string (`SSH-2.0`).
   - Diffie-Hellman Group Key Exchange calculating shared secret $K$ and exchange hash $H$.
   - Host private key signature over $H$ for server authentication.
   - User authentication (`ssh-userauth`).
   - Secure encrypted PTY terminal allocation.

3. **IPsec Encapsulating Security Payload (ESP)**:
   - **Transport Mode**: Host-to-host protection; encrypts upper-layer payload while preserving IP headers.
   - **Tunnel Mode (VPN)**: Gateway-to-gateway; encapsulates and encrypts the entire original IP datagram beneath a new gateway header.
   - Color-coded datagram dissection showing plaintext headers, ESP headers, encrypted payloads, trailers, and HMAC-SHA256 ICVs.

---

## API Specification (Port 5002)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health and active session count |
| `POST` | `/api/tls/init` | Allocates new stateful TLS session |
| `POST` | `/api/tls/step/<1-5>` | Advances through Client Hello, Server Hello, Key Exchange, PRF, Finished |
| `POST` | `/api/tls/send-data` | Transmits payload encrypted with session's AES-128-GCM key |
| `POST` | `/api/ssh/init` | Allocates new stateful SSH-2.0 session |
| `POST` | `/api/ssh/step/<1-5>` | Advances through Version, DH KEX, Server Auth, User Auth, PTY Shell |
| `POST` | `/api/ipsec/analyze` | Generates structured ESP datagram breakdown for Transport vs Tunnel Mode |

---

## Unit Testing
To execute the unit test suite:
```bash
python test_project2.py
```
