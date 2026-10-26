# Project 3: "Citadel Defense" — Perimeter Firewall & Statistical Intrusion Detection System

## Executive Summary
**Citadel Defense** is an integrated network defense platform built for the **ALM-2** curriculum. It provides granular firewall policy filtering, Bastion Host isolation, dual-engine intrusion detection (deterministic rule signatures and Gaussian statistical anomaly detection using NumPy & Pandas), and a comprehensive threat intelligence encyclopedia.

---

## Architectural Modules

1. **Firewall Rule Engine & Bastion Perimeter**:
   - Priority-ordered packet matching (Direction, Protocol, Source IP/CIDR, Destination IP/CIDR, Port).
   - Strict default-drop fallback policy.
   - Dedicated **Bastion Host** configuration (`10.0.0.5`) monitoring ports 22/443 and enforcing management subnet isolation (`192.168.1.0/24`).

2. **Rule-Based Intrusion Detection System (Signature IDS)**:
   - **SSH Brute-Force**: Flags $\ge 5$ failed authentications within 60s from the same IP (High Severity).
   - **Insecure Protocol Alert**: Detects unencrypted Telnet traffic on Port 23 (Medium Severity).
   - **Reconnaissance Port Scan**: Detects multi-port sequential probing sweeps (High Severity).

3. **Statistical Anomaly Intrusion Detection Engine (3-Sigma Gaussian Model)**:
   - Dynamic baseline traffic modeling powered by **NumPy** and **Pandas**.
   - Calculates real-time running mean ($\mu$) and standard deviation ($\sigma$).
   - Flags volumetric traffic surges (e.g. SYN Floods) exceeding:
     $$\text{Threshold} = \mu + 3\sigma$$
   - Displays computed Z-score:
     $$Z = \frac{x - \mu}{\sigma}$$

4. **Threat Intelligence Encyclopedia**:
   - Educational taxonomy covering File Infector Viruses, Boot Sector Viruses, Macro Viruses, Self-Propagating Network Worms (Morris, WannaCry), and Bastion defense countermeasures.

---

## REST API Specification (Port 5003)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service status and bastion IP |
| `GET` | `/api/firewall/rules` | Retrieves active rules and Bastion Host configuration |
| `POST` | `/api/firewall/rules` | Inserts new firewall rule with priority weighting |
| `PUT` | `/api/firewall/rules/<id>` | Updates an existing firewall rule |
| `DELETE` | `/api/firewall/rules/<id>` | Deletes a firewall rule |
| `POST` | `/api/firewall/inspect` | Evaluates packet against firewall rules |
| `POST` | `/api/firewall/bastion` | Updates Bastion Host parameters |
| `POST` | `/api/ids/traffic/generate` | Injects traffic vectors and checks for signature/anomaly alerts |
| `GET` | `/api/ids/alerts` | Fetches live alert stream |
| `DELETE` | `/api/ids/alerts` | Clears all IDS alerts |
| `GET` | `/api/ids/metrics` | Returns 3-sigma statistical baseline and rate history |
| `GET` | `/api/threats` | Retrieves encyclopedia articles |

---

## Unit Testing
To run the dedicated unit test suite:
```bash
python test_project3.py
```
