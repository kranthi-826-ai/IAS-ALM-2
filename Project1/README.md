# Project 1: "AegisCrypt" — Asymmetric Cryptography & PKI Framework

## Executive Summary
**AegisCrypt** is a modular cryptographic subsystem designed for the **ALM-2** (Active Learning Management) evaluation. It provides full-stack tooling for asymmetric key lifecycle management, Public Key Infrastructure (PKI) certification, interactive RSA encryption/signing, Diffie-Hellman mathematical key agreement, and Elgamal digital signatures hardened with SHA-512 cryptographic digests.

---

## Capabilities & Theoretical Framework

1. **Identity & PKI Certificate Authority (CA)**:
   - Automated generation of 2048-bit RSA key pairs.
   - Built-in Certificate Authority engine issuing X.509 v3 digital certificates (`.crt`) binding client identities to public keys.
   - Secure SQLite persistence (`aegiscrypt.db`) for credentials and cryptographic artifacts.

2. **Interactive RSA Cryptosystem**:
   - **RSA-OAEP (Optimal Asymmetric Encryption Padding)**: Uses SHA-256 and Mask Generation Function 1 (MGF1) to prevent chosen-ciphertext attacks.
   - **RSA-PSS (Probabilistic Signature Scheme)**: State-of-the-art digital signatures with randomized salt per PKCS #1 v2.1.
   - Instant PEM-encoded key inspection.

3. **Diffie-Hellman Key Agreement Matrix**:
   - Discrete-logarithm based key agreement over insecure channels.
   - 4-phase step-by-step visual arithmetic:
     $$\text{Alice: } A = g^a \pmod p \quad\quad \text{Bob: } B = g^b \pmod p$$
     $$\text{Shared Secret: } s = B^a \pmod p = A^b \pmod p$$
   - Supports educational small primes, medium primes, and RFC 3526 1536-bit groups.

4. **Elgamal Digital Signatures with SHA-512**:
   - Implements discrete log digital signatures over prime field $\mathbb{Z}_p^*$.
   - Computes 512-bit SHA-512 digests reduced modulo $(p - 1)$.
   - Ephemeral key $k$ generation with extended Euclidean algorithm modular inversion.
   - Verification equality: $g^{H(m)} \equiv y^r \cdot r^s \pmod p$.

---

## REST API Specification (Port 5001)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service status and runtime telemetry |
| `POST` | `/api/auth/register` | Enrolls user identity, generates RSA-2048 keys, issues X.509 CA cert |
| `POST` | `/api/auth/login` | Authenticates user and returns active keypair and cert |
| `GET` | `/api/users/list` | Lists all enrolled cryptographic identities |
| `GET` | `/api/pki/download-cert/<id>` | Downloads user's X.509 certificate file (`.crt`) |
| `GET` | `/api/rsa/generate` | Generates on-demand RSA-2048 keypair |
| `POST` | `/api/rsa/encrypt` | RSA-OAEP encryption with SHA-256 |
| `POST` | `/api/rsa/decrypt` | RSA-OAEP decryption with SHA-256 |
| `POST` | `/api/rsa/sign` | RSA-PSS digital signature computation |
| `POST` | `/api/rsa/verify` | Signature integrity verification |
| `POST` | `/api/dh/setup` | Initializes Diffie-Hellman domain parameters |
| `POST` | `/api/dh/calculate-step` | Executes steps 1-4 of Diffie-Hellman with formula breakdowns |
| `GET` | `/api/elgamal/keygen` | Generates Elgamal domain parameters and keypair |
| `POST` | `/api/elgamal/hash` | Computes SHA-512 message digest |
| `POST` | `/api/elgamal/sign` | Generates Elgamal digital signature $(r, s)$ |
| `POST` | `/api/elgamal/verify` | Verifies Elgamal digital signature |

---

## Verification & Unit Testing
To run the dedicated unit test suite:
```bash
python test_project1.py
```
