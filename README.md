# KL University (KLH) • Active Learning Management Project - 2 (ALM-2)
## AegisOps: Applied Cyber Defense & Cryptography Operations Suite

---

## 🌟 Executive Overview
This repository contains the complete, production-grade implementation of **ALM-2 (Active Learning Management Project 2)**.

All three required projects are developed in their designated directories (`Project1/`, `Project2/`, `Project3/`) with standalone modular Python backends, and united under a high-performance **Unified AegisOps Command Console (React 19 + Vite)** with real-time health telemetry.

---

## 📁 Repository Directory Structure

```text
ALM2-V/
├── Project1/                               # Project 1: "AegisCrypt"
│   ├── crypto_engine.py                    # Object-Oriented Cryptographic Primitives Engine
│   ├── app.py                              # Flask Backend (Port 5001): PKI, RSA-OAEP/PSS, DH, Elgamal/SHA-512
│   ├── test_project1.py                    # Complete Unit Test Suite (All 5 tests passing)
│   ├── requirements.txt                    # Python dependencies
│   └── README.md                           # Project 1 Documentation
│
├── Project2/                               # Project 2: "NexusTunnel"
│   ├── tunnel_engine.py                    # Transport Layer Protocols & IPsec ESP Analyzer
│   ├── app.py                              # Flask Backend (Port 5002): TLS 1.2/1.3, SSH-2.0, IPsec ESP
│   ├── test_project2.py                    # Complete Unit Test Suite (All 4 tests passing)
│   ├── requirements.txt                    # Python dependencies
│   └── README.md                           # Project 2 Documentation
│
├── Project3/                               # Project 3: "Citadel Defense"
│   ├── defense_engine.py                   # Firewall Evaluator, Bastion Manager & 3-Sigma Anomaly Engine
│   ├── app.py                              # Flask Backend (Port 5003): Firewall Rules, IDS, Threat Encyclopedia
│   ├── test_project3.py                    # Complete Unit Test Suite (All 4 tests passing)
│   ├── requirements.txt                    # Python dependencies
│   └── README.md                           # Project 3 Documentation
│
├── dashboard/                              # Unified Command Console (React 19 + Vite)
│   ├── src/
│   │   ├── components/
│   │   │   ├── OverviewConsole.jsx         # Operations Deck with Architecture & Deliverables Matrix
│   │   │   ├── AegisCryptConsole.jsx       # Interactive PKI, RSA, DH, and Elgamal/SHA-512 UI
│   │   │   ├── NexusTunnelConsole.jsx      # Stateful TLS/SSH Handshakes & IPsec ESP Diagrams
│   │   │   └── CitadelConsole.jsx          # Firewall Manager, Attack Simulator, IDS & Anomaly Telemetry
│   │   ├── App.jsx                         # Master App with HUD Navigation & Live Polling
│   │   └── index.css                       # Bespoke Cyber-Dark Theme (Electric Indigo & Amber)
│   ├── vite.config.js                      # Configured for Port 3000 with Microservice Proxies
│   └── package.json
│
├── run_all.py                              # Master Launcher (Spawns all 3 backends + React UI)
├── run_all.bat                             # One-Click Windows Batch Launcher
└── README.md                               # Master ALM-2 Documentation
```

---

## 🚀 Quick Start Guide

### 1. Launch All Services Simultaneously
Execute the master launcher from the root directory:
```bash
python run_all.py
```
*Or double-click `run_all.bat` on Windows.*

This will automatically launch:
- **Project 1 Backend (AegisCrypt):** `http://localhost:5001`
- **Project 2 Backend (NexusTunnel):** `http://localhost:5002`
- **Project 3 Backend (Citadel Defense):** `http://localhost:5003`
- **Command Dashboard UI:** `http://localhost:3000`

Open **`http://localhost:3000`** in your web browser to access the complete unified operations center.

---

## 🔍 Detailed Deliverables Verification Matrix

| Project | Feature Required in ALM-2 Specification | Implementation Location | Test Status |
|---|---|---|:---:|
| **Project 1** | User Authentication & PKI Key Management (RSA-2048, SQLite, X.509 CA Certificate download) | `Project1/app.py` (`/api/auth/*`, `/api/pki/*`) |  Passed |
| **Project 1** | Interactive RSA Module (OAEP Encrypt/Decrypt, PSS Sign/Verify, PEM Key Viewer) | `Project1/app.py` (`/api/rsa/*`) |  Passed |
| **Project 1** | Diffie-Hellman Key Exchange Visualizer (Alice & Bob dual-panels, steps 1-4, shared secret) | `Project1/app.py` (`/api/dh/*`) |  Passed |
| **Project 1** | Elgamal Digital Signature & SHA-512 Hashing (Domain parameters, hash, sign, verify) | `Project1/app.py` (`/api/elgamal/*`) |  Passed |
| **Project 2** | TLS/SSL Handshake Simulation (Steps 1-5: Client Hello, Server Hello & Cert, Key Exchange, PRF Session Keys, Finished) | `Project2/app.py` (`/api/tls/*`) |  Passed |
| **Project 2** | Symmetric Transmission over TLS Tunnel (AES-128-GCM with derived `client_write_key`) | `Project2/app.py` (`/api/tls/send-data`) |  Passed |
| **Project 2** | Simplified SSH Connection Simulation (Steps 1-5: Version exchange, DH KEX, Host Auth, User Auth, PTY Shell) | `Project2/app.py` (`/api/ssh/*`) |  Passed |
| **Project 2** | IP Security (IPsec) ESP Overview (Toggle Transport vs Tunnel Mode, color-coded packet blocks) | `Project2/app.py` (`/api/ipsec/*`) |  Passed |
| **Project 3** | Firewall Rule Manager (Add/edit/delete rules, priority order, default drop, live packet inspector) | `Project3/app.py` (`/api/firewall/*`) |  Passed |
| **Project 3** | Bastion Host Configuration (Designate server `10.0.0.5`, restrict management subnet `192.168.1.0/24`, monitor ports 22, 443) | `Project3/app.py` (`/api/firewall/bastion`) |  Passed |
| **Project 3** | Network Traffic Generator (Normal HTTP, SSH Brute Force, Telnet, Port Scan, SYN Flood) | `Project3/app.py` (`/api/ids/traffic/generate`) |  Passed |
| **Project 3** | Rule-Based IDS (Detects 5+ failed SSH logins in 1 min, port 23 Telnet, sequential port scan) | `Project3/app.py` (`/api/ids/alerts`) |  Passed |
| **Project 3** | Statistical Anomaly IDS (NumPy/Pandas 3-Sigma Gaussian model with dynamic threshold chart & Z-scores) | `Project3/app.py` (`/api/ids/metrics`) |  Passed |
| **Project 3** | Threat Encyclopedia (Viruses: File Infector, Boot Sector, Macro; Worms; Defense countermeasures) | `Project3/app.py` (`/api/threats`) |  Passed |
| **Master UI** | Unified Dashboard linking Project 1, 2, and 3 in one single interface with one-click navigation | `dashboard/src/App.jsx` |  Built & Verified |

---

## 🧪 Unit Test Execution

Each project features an independent unit test suite:

```bash
# Project 1 Unit Tests
cd Project1
python test_project1.py

# Project 2 Unit Tests
cd Project2
python test_project2.py

# Project 3 Unit Tests
cd Project3
python test_project3.py
```
