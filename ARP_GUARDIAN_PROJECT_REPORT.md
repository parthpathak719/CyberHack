# ARP Guardian — Project Report

## ARP Spoofing Detection & Automated Network Segmentation

---

**Project Title:** ARP Guardian  
**MITRE ATT&CK Technique:** T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning  
**Architecture:** On-Premises LAN  
**Difficulty Level:** Medium  
**Tech Stack:** Python (Scapy, Flask, pysnmp), Node.js, Docker, HTML/CSS/Canvas  

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Problem Statement](#3-problem-statement)
4. [MITRE ATT&CK Framework Alignment](#4-mitre-attck-framework-alignment)
5. [System Architecture](#5-system-architecture)
6. [Technology Stack](#6-technology-stack)
7. [Module-Level Design & Implementation](#7-module-level-design--implementation)
8. [Detection Heuristics](#8-detection-heuristics)
9. [Automated Response — VLAN Quarantine](#9-automated-response--vlan-quarantine)
10. [Simulation Engine](#10-simulation-engine)
11. [Web Dashboard](#11-web-dashboard)
12. [Docker Deployment](#12-docker-deployment)
13. [Testing Strategy](#13-testing-strategy)
14. [Threat Model & Risk Assessment](#14-threat-model--risk-assessment)
15. [Known Limitations & Bypasses](#15-known-limitations--bypasses)
16. [Results & Demonstration](#16-results--demonstration)
17. [Future Scope](#17-future-scope)
18. [Conclusion](#18-conclusion)
19. [References](#19-references)

---

## 1. Abstract

ARP Guardian is a continuous ARP watch daemon designed for on-premises local area networks (LANs). It detects ARP cache poisoning attacks — a technique classified under MITRE ATT&CK T1557.002 — by monitoring real-time ARP traffic using six multi-heuristic detection rules. Upon confirming an attack, it automatically quarantines the attacking host within 30 seconds by pushing VLAN isolation rules to a managed network switch. The system provides a live web dashboard for real-time network topology visualization, alert monitoring, and quarantine status tracking. ARP Guardian can operate in three modes: live packet capture, Docker-based isolated LAN simulation, and a fully software-based simulation mode that requires no root access or Docker.

---

## 2. Introduction

The Address Resolution Protocol (ARP) is a Layer 2 protocol used in IPv4 networks to resolve IP addresses to MAC addresses. ARP is inherently stateless and trust-based — hosts accept ARP replies without verifying that they sent a corresponding request. This fundamental design flaw enables an attacker within the same broadcast domain to send forged (spoofed) ARP replies, thereby poisoning the ARP caches of other hosts and positioning themselves as a man-in-the-middle (MitM).

ARP cache poisoning attacks are trivial to execute using freely available tools (e.g., `arpspoof`, `ettercap`, `bettercap`) and remain a persistent threat in enterprise LANs, campus networks, and any shared Ethernet/WiFi environment. Once established, a MitM attacker can intercept plaintext credentials, session tokens, DNS queries, and sensitive data flowing between victims and the network gateway.

ARP Guardian addresses this threat by implementing a continuous passive ARP monitoring daemon that detects and responds to ARP spoofing attacks in real time.

---

## 3. Problem Statement

An insider threat is performing ARP cache poisoning attacks on the LAN to intercept traffic between workstations and the default gateway. The objective of this project is to build a system that:

1. **Detects** IP-to-MAC binding changes (spoofed ARP replies) within 30 seconds of attack initiation.
2. **Identifies** the attacking host's MAC address using multiple corroborating heuristics.
3. **Quarantines** the attacker by pushing a VLAN isolation rule to a managed switch (simulated via REST API or real via SNMP).
4. **Reports** the attack through a live web dashboard and structured JSON logs.
5. **Aligns** with the MITRE ATT&CK framework for standardized threat classification and response.

---

## 4. MITRE ATT&CK Framework Alignment

The project is fully aligned with the MITRE ATT&CK framework to provide standardized threat intelligence.

### 4.1 Technique Mapping

| Field              | Value                                                   |
|--------------------|---------------------------------------------------------|
| Technique ID       | T1557.002                                               |
| Technique Name     | Adversary-in-the-Middle: ARP Cache Poisoning             |
| Tactic             | Credential Access (TA0006), Collection (TA0009)         |
| Platform           | Linux, macOS, Windows                                   |
| Permissions        | User (raw socket / admin on Windows)                    |
| Data Sources       | DS0029: Network Traffic (Content + Flow)                |

### 4.2 Data Sources Used

- **Network Traffic Content (DS0029):** ARP packet fields — operation code (op), source hardware address (hwsrc), source protocol address (psrc), destination hardware address (hwdst), and destination protocol address (pdst).
- **Network Traffic Flow (DS0029):** ARP packet rate per source MAC address used for storm and flood detection.

### 4.3 Mitigations Implemented

| MITRE ID | Mitigation                           | Implementation in ARP Guardian              |
|----------|--------------------------------------|---------------------------------------------|
| M1037    | Filter Network Traffic               | VLAN quarantine isolates the attacker       |
| M1035    | Limit Access to Resource Over Network| Port-based isolation via VLAN 999           |
| M1031    | Network Intrusion Prevention         | Continuous passive ARP monitoring           |
| M1017    | User Training                        | Dashboard raises awareness of insider risks |

### 4.4 Kill Chain Position

ARP cache poisoning sits at the **Credential Access** stage of the attack kill chain:

```
Reconnaissance → Initial Access → Execution → Persistence →
Privilege Escalation → Defence Evasion → ★ Credential Access ★ →
Discovery → Lateral Movement → Collection → Exfiltration
```

By intercepting traffic at this stage, the attacker can capture plaintext credentials, session tokens, API keys, and DNS queries transiting the LAN.

---

## 5. System Architecture

ARP Guardian follows a **pipeline architecture** with four stages:

```
Capture → Detect → Respond → Report
```

### 5.1 Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        ARP Guardian                              │
│                                                                  │
│  ┌───────────────┐    ┌─────────────────┐    ┌───────────────┐  │
│  │  ARP Monitor  │───→│ Threat Detector │───→│ Alert Engine  │  │
│  │  (scapy)      │    │ (6 heuristics)  │    │               │  │
│  └───────────────┘    └────────┬────────┘    └───────┬───────┘  │
│                                │                     │          │
│  ┌───────────────┐    ┌────────┴────────┐    ┌───────┴───────┐  │
│  │  ARP Cache    │←───│   Models +      │    │ VLAN Manager  │  │
│  │  (binding DB) │    │  ATT&CK Map     │    │ (quarantine)  │  │
│  └───────────────┘    └─────────────────┘    └───────┬───────┘  │
│                                                      │          │
│  ┌───────────────┐                           ┌───────┴───────┐  │
│  │  REST API     │                           │ Switch Client │  │
│  │  (dashboard)  │                           │ (API / SNMP)  │  │
│  └───────┬───────┘                           └───────┬───────┘  │
└──────────┼───────────────────────────────────────────┼──────────┘
           │                                           │
    ┌──────┴──────┐                            ┌───────┴───────┐
    │  Dashboard  │                            │ Managed Switch│
    │  (Browser)  │                            │ (Simulated)   │
    └─────────────┘                            └───────────────┘
```

### 5.2 Data Flow

**Stage 1 — Capture:**  
`Network Interface → scapy sniff (filter="arp") → ArpEvent`

The ArpMonitor runs in a daemon thread. Each ARP packet is parsed into an `ArpEvent` dataclass with fields: `src_mac`, `dst_mac`, `src_ip`, `dst_ip`, `operation`, and `is_gratuitous`.

**Stage 2 — Detection:**  
`ArpEvent → ArpCache.update() → ThreatDetector.analyze() → Alert[]`

The ArpCache maintains IP-to-MAC bindings (thread-safe). The ThreatDetector runs 6 parallel heuristics on each event. Detection is synchronous per-packet with no batching delay.

**Stage 3 — Response:**  
`Alert → AlertEngine.process() → VlanManager.quarantine() → SwitchClient`

The AlertEngine filters alerts and decides whether to auto-quarantine. The VlanManager resolves the attacker MAC to a switch port and issues a VLAN change command.

**Stage 4 — Report:**  
`State → REST API → Dashboard (polling every 2s)`

An embedded HTTP server serves JSON API endpoints. The browser dashboard polls these endpoints and renders the real-time state.

### 5.3 Concurrency Model

```
Main Thread
├── API Server Thread (HTTPServer on port 8081)
├── ARP Monitor Thread (scapy sniff) or Simulator Thread
└── Signal Handler (SIGINT → graceful shutdown)
```

All shared state is protected by `threading.Lock` instances in `ArpCache`, `ThreatDetector`, `AlertEngine`, and `VlanManager`.

---

## 6. Technology Stack

| Component              | Technology                          | Purpose                                |
|------------------------|-------------------------------------|----------------------------------------|
| ARP packet capture     | Python + Scapy ≥ 2.5.0             | Raw ARP packet sniffing and parsing    |
| SNMP switch control    | pysnmp ≥ 4.4.12                     | Real switch VLAN management via SNMP   |
| HTTP requests          | requests ≥ 2.31.0                   | Simulated switch REST API client       |
| Switch simulator       | Flask ≥ 3.0.0                       | REST API emulating a managed switch    |
| LAN simulation         | Docker + docker-compose             | Isolated network environment           |
| Packet validation      | Wireshark / tcpdump                 | Manual pcap inspection                 |
| Dashboard server       | Node.js / Python HTTP server        | Static file serving + API proxy        |
| Dashboard frontend     | HTML + CSS + Canvas JS              | Real-time visualization in browser     |

---

## 7. Module-Level Design & Implementation

### 7.1 Project Structure

```
cyber_hack/
├── src/arp_guardian/            # Core Python package
│   ├── __main__.py             # CLI entry point + embedded REST API
│   ├── arp_monitor.py          # Scapy packet capture daemon
│   ├── arp_cache.py            # ARP binding table manager
│   ├── detector.py             # Threat detection engine (6 heuristics)
│   ├── vlan_manager.py         # VLAN quarantine orchestrator
│   ├── switch_client.py        # Simulated switch REST client
│   ├── snmp_client.py          # pysnmp client for real switches
│   ├── alert_engine.py         # Alert processing and dispatch
│   ├── simulator.py            # Simulation mode (synthetic traffic)
│   ├── config.py               # Configuration management
│   ├── models.py               # Data models + ATT&CK mapping
│   └── logger.py               # Structured JSON logging
├── switch_simulator/           # Flask simulated switch
│   └── app.py
├── attacker/                   # ARP spoofing demo script
│   └── arp_spoof.py
├── dashboard/                  # Web dashboard
│   ├── server.js / server.py   # Dashboard server (Node.js or Python)
│   ├── index.html              # Dashboard page
│   ├── style.css               # Premium dark theme
│   └── app.js                  # Canvas topology + real-time UI
├── tests/                      # Unit tests (pytest)
│   ├── test_arp_cache.py
│   ├── test_detector.py
│   └── test_vlan_manager.py
├── scripts/                    # Automation scripts
│   ├── run_demo.sh             # Full demo launcher
│   ├── capture_arp.sh          # Wireshark capture helper
│   └── capture_traffic.sh      # Traffic capture helper
├── docker-compose.yml          # Isolated LAN simulation
├── Dockerfile.monitor          # Monitor container
├── Dockerfile.attacker         # Attacker container
├── Dockerfile.switch           # Switch simulator container
├── Makefile                    # Build/run command shortcuts
├── requirements.txt            # Python dependencies
├── THREAT_MODEL.md             # Detailed threat model document
└── ARCHITECTURE.md             # Architecture documentation
```

### 7.2 Core Modules

#### 7.2.1 `models.py` — Data Models

Defines all structured types using Python `dataclasses`:

- **`ArpEvent`** — Represents a captured ARP packet with fields for source/destination MAC and IP, ARP operation type (request/reply/gratuitous), a unique ID, and a timestamp.
- **`ArpEntry`** — A single row in the ARP binding table: IP, MAC, first/last seen timestamps, VLAN ID, trust status, and a change counter.
- **`Alert`** — A detection alert with severity level, detection type, human-readable description, source MAC/IP, MITRE technique reference, and an `auto_response` flag indicating whether automatic quarantine should be triggered.
- **`QuarantineAction`** — Records a VLAN isolation action: attacker MAC/IP, switch port, source and destination VLAN IDs, method used (SNMP or REST API), and outcome status (pending/applied/failed/released).
- **`MitreMapping`** — Stores the MITRE ATT&CK T1557.002 technique reference including technique ID, name, tactic, data sources, mitigations, and detection notes.

Enumerations defined: `Severity` (info, low, medium, high, critical), `ArpOperation` (request, reply, gratuitous), `DetectionType` (6 detection categories), and `QuarantineStatus` (pending, applied, failed, released).

#### 7.2.2 `arp_cache.py` — ARP Binding Table Manager

The `ArpCache` class maintains a thread-safe IP-to-MAC binding table. Key operations:

- **`seed(ip, mac, is_trusted)`** — Pre-populates a known-good binding (e.g., the default gateway). Trusted entries generate higher-severity alerts if overwritten.
- **`update(event)`** — Processes an ARP event. If the IP already exists in the table with a different MAC, it records the change, increments the change counter, appends to the change history, and returns the `(old_mac, new_mac)` tuple. If the MAC is the same, it refreshes the timestamp. If the IP is new, it creates a new entry.
- **`get_change_count(ip)`** — Returns how many times an IP's MAC has changed (used by the flapping detector).
- **`find_ips_by_mac(mac)`** — Reverse lookup: finds all IPs associated with a given MAC.
- **`mark_quarantined(ip, vlan_id)`** — Updates the VLAN field when a host is quarantined.

All operations are protected by a `threading.Lock` for thread safety.

#### 7.2.3 `detector.py` — Threat Detection Engine

The `ThreatDetector` class is the core intelligence module. It processes each ARP event through six parallel heuristic checks (detailed in Section 8). Key design decisions:

- Detection is **synchronous per-packet** — no batching or polling delay.
- Each heuristic independently evaluates the event and may produce zero or more `Alert` objects.
- Rate-based detections (ARP storm, gratuitous flood) use sliding time windows with configurable thresholds.
- The detector tracks the **detection timing KPI**: it records when the first attack packet is detected and computes the elapsed time since attack initiation. The target is sub-30-second detection.

#### 7.2.4 `alert_engine.py` — Alert Processing & Dispatch

The `AlertEngine` connects the detection output to the quarantine response:

1. Stores every alert in memory and persists it to `data/alerts.json`.
2. If `auto_quarantine` is enabled and the alert's `auto_response` flag is set, it triggers `VlanManager.quarantine()`.
3. Maintains a set of already-quarantined MACs to avoid duplicate quarantine actions.

#### 7.2.5 `vlan_manager.py` — VLAN Quarantine Orchestrator

The `VlanManager` executes the automated response:

1. **Resolves** the attacker MAC to a switch port using the switch API's MAC address table lookup, with a fallback to a static port map.
2. **Applies** the VLAN change via either the simulated switch REST API (`POST /api/port/vlan`) or real SNMP SET commands.
3. **Records** the quarantine action with its outcome (applied/failed) to `data/quarantine_log.json`.
4. Supports **release** — moving a previously quarantined MAC back to the normal VLAN.

Port map defaults for the demo environment:

| MAC Address           | Port  | Description |
|-----------------------|-------|-------------|
| 02:42:c0:a8:64:01     | Gi0/1 | Gateway     |
| 02:42:c0:a8:64:0a     | Gi0/2 | Workstation |
| 02:42:c0:a8:64:14     | Gi0/3 | Server      |
| 02:42:c0:a8:64:1e     | Gi0/4 | Attacker    |

#### 7.2.6 `switch_client.py` — Switch REST API Client

Communicates with the simulated switch via HTTP:

- `GET /api/mac-table?mac=<mac>` — Looks up which port a MAC is connected to.
- `POST /api/port/vlan` — Moves a port to a different VLAN (the quarantine action).

#### 7.2.7 `snmp_client.py` — SNMP Client for Real Switches

For production deployments with real Cisco or Q-BRIDGE-compliant switches:

- Uses `pysnmp` to issue SNMP SET commands.
- Cisco VLAN Membership MIB OID: `1.3.6.1.4.1.9.9.68.1.2.2.1.2.<ifIndex>`
- Q-BRIDGE MIB OID: `1.3.6.1.2.1.17.7.1.4.5.1.1.<port>`

#### 7.2.8 `__main__.py` — CLI Entry Point & REST API

The main module orchestrates all components:

1. Parses CLI arguments (`--simulate`, `--iface`, `--snmp`, `--no-quarantine`, `--api-port`, `--switch-url`).
2. Initialises all components in the correct dependency order.
3. Starts an embedded HTTP API server (default port 8081) in a daemon thread.
4. Starts either the live ArpMonitor or the Simulator.
5. Registers SIGINT/SIGTERM handlers for graceful shutdown.
6. On shutdown, writes a final summary to `data/final_summary.json`.

**REST API Endpoints:**

| Endpoint           | Method | Description                          |
|--------------------|--------|--------------------------------------|
| `/api/health`      | GET    | Health check                         |
| `/api/status`      | GET    | Overall system status                |
| `/api/events`      | GET    | Raw ARP event log                    |
| `/api/alerts`      | GET    | Detection alerts                     |
| `/api/cache`       | GET    | ARP binding table                    |
| `/api/quarantine`  | GET    | Quarantine actions                   |
| `/api/stats`       | GET    | Detection statistics                 |
| `/api/mitre`       | GET    | MITRE ATT&CK mapping                |
| `/api/topology`    | GET    | Network host topology                |

---

## 8. Detection Heuristics

The threat detection engine implements six complementary heuristics. Each check runs independently on every ARP packet, providing defence-in-depth.

### 8.1 MAC Binding Change Detection

| Property    | Value                                        |
|-------------|----------------------------------------------|
| Severity    | MEDIUM (normal host) / HIGH (trusted host) / CRITICAL (gateway) |
| Trigger     | IP's MAC binding changes from the cached value |
| Confidence  | High                                         |

When an ARP event contains an IP that already exists in the binding table with a different MAC, an alert is raised. The severity is escalated if the IP belongs to the gateway or a trusted host. Each MAC change increments a per-IP counter used by the flapping detector.

### 8.2 MAC Flapping Detection

| Property    | Value                                        |
|-------------|----------------------------------------------|
| Severity    | CRITICAL                                     |
| Trigger     | ≥2 MAC changes observed for the same IP      |
| Confidence  | Very High                                    |

Rapid MAC oscillation on the same IP is a strong indicator of active ARP cache poisoning. If the change count for an IP reaches or exceeds the configured threshold (default: 2), a CRITICAL alert is raised confirming an active attack, and automatic quarantine is triggered.

### 8.3 Gateway Impersonation Detection

| Property    | Value                                        |
|-------------|----------------------------------------------|
| Severity    | CRITICAL                                     |
| Trigger     | A non-gateway MAC sends ARP claiming the gateway IP |
| Confidence  | Very High                                    |

This check compares the source MAC of any ARP packet claiming the gateway IP against the known (seeded) gateway MAC. A mismatch is a definitive ARP spoofing indicator and immediately triggers quarantine.

### 8.4 Gratuitous ARP Flood Detection

| Property    | Value                                        |
|-------------|----------------------------------------------|
| Severity    | HIGH                                         |
| Trigger     | ≥5 unsolicited ARP announcements from one IP in 60 seconds |
| Confidence  | Medium                                       |

A sliding 60-second window tracks gratuitous ARP packets per source IP. Exceeding the threshold indicates a likely poisoning attempt, as attackers often send gratuitous ARPs to rapidly propagate spoofed bindings.

### 8.5 ARP Storm Detection

| Property    | Value                                        |
|-------------|----------------------------------------------|
| Severity    | MEDIUM                                       |
| Trigger     | ≥50 ARP packets from one MAC in 60 seconds   |
| Confidence  | Medium                                       |

A rate limiter per source MAC detects abnormally high ARP traffic. This may indicate network reconnaissance, ARP-based scanning, or an aggressive poisoning campaign.

### 8.6 Duplicate IP Detection

| Property    | Value                                        |
|-------------|----------------------------------------------|
| Severity    | HIGH                                         |
| Trigger     | Two different MACs advertise the same IP simultaneously |
| Confidence  | High                                         |

When a new ARP event claims an IP that is already in the cache with a different MAC (before the change is recorded as a "change"), a duplicate IP alert is raised. This catches the initial conflict before it is recorded as a binding change.

### Detection Timing Requirement

The system is designed to detect ARP spoofing within **30 seconds** of attack initiation. This is achieved by:

- Continuous passive ARP sniffing (no polling interval).
- Immediate comparison against the trusted binding table.
- Synchronous per-packet heuristic evaluation.

In testing, detection typically occurs in **< 1 second** from attack initiation.

---

## 9. Automated Response — VLAN Quarantine

### 9.1 Quarantine Workflow

When an attack is confirmed (CRITICAL alert with `auto_response=True`):

1. **Identify:** Extract the attacker's MAC address from the spoofed ARP reply.
2. **Resolve:** Look up the MAC in the switch's MAC address table to determine the physical port.
3. **Isolate:** Move the port from VLAN 1 (default) to VLAN 999 (quarantine) via REST API or SNMP SET.
4. **Log:** Record the quarantine action with timestamp, evidence, and outcome status.
5. **Report:** Update the dashboard and JSON logs.

### 9.2 VLAN Change Mechanisms

| Method              | Endpoint / OID                              | Use Case              |
|---------------------|---------------------------------------------|-----------------------|
| REST API (Simulated)| `POST /api/port/vlan { port, vlan_id }`     | Demo / Docker         |
| SNMP SET (Cisco)    | `1.3.6.1.4.1.9.9.68.1.2.2.1.2.<ifIndex>`   | Real Cisco switches   |
| SNMP SET (Q-BRIDGE) | `1.3.6.1.2.1.17.7.1.4.5.1.1.<port>`        | Generic managed switches |

### 9.3 Switch Simulator

The Flask-based switch simulator (`switch_simulator/app.py`) emulates a Cisco-style managed switch with:

- A MAC address table mapping MACs to ports.
- A VLAN database with VLAN 1 (default), VLAN 10 (servers), VLAN 20 (workstations), and VLAN 999 (quarantine).
- Port enable/disable and VLAN assignment capabilities.
- An action log recording all VLAN changes.
- Dynamic MAC fallback: unknown MACs are automatically mapped to the attacker port (Gi0/4) for seamless demo operation.

---

## 10. Simulation Engine

The `Simulator` class (`simulator.py`) generates synthetic ARP events for demonstration without requiring real network access or Docker. It runs a three-phase scenario:

### Phase 1 — Normal Traffic (0–10 seconds)

Legitimate ARP request/reply pairs between gateway, workstation, and server. Occasional gratuitous ARP announcements from the server. Events are emitted every 2 seconds.

### Phase 2 — Attack (10–40 seconds)

The attacker sends spoofed ARP replies claiming to be the gateway (192.168.100.1) but using the attacker's MAC (02:42:c0:a8:64:1e). This poisons the victim's ARP cache. Events are emitted every 0.5 seconds, including:

- Spoofed unicast ARP replies directed at the workstation.
- Spoofed gratuitous ARP broadcasts claiming the gateway IP.
- Occasional legitimate background traffic (30% probability).

### Phase 3 — Post-Quarantine (40 seconds onwards)

After the attacker is quarantined, only normal traffic continues. The attacker's traffic ceases, demonstrating the effectiveness of the quarantine response.

### Simulated Network Topology

| Host        | IP Address      | MAC Address         | Role       |
|-------------|-----------------|---------------------|------------|
| Gateway     | 192.168.100.1   | 02:42:c0:a8:64:01   | Router     |
| Workstation | 192.168.100.10  | 02:42:c0:a8:64:0a   | Victim     |
| Server      | 192.168.100.20  | 02:42:c0:a8:64:14   | Server     |
| Attacker    | 192.168.100.30  | 02:42:c0:a8:64:1e   | Attacker   |

---

## 11. Web Dashboard

The dashboard is a single-page web application that provides real-time visibility into the ARP Guardian system.

### 11.1 Dashboard Components

1. **Network Topology Canvas** — An HTML5 Canvas-rendered network diagram showing all hosts (gateway, workstation, server, attacker) connected through a central switch. Quarantined hosts are highlighted with red glow effects and dashed connection lines. Active attack arrows pulse with animation.

2. **Statistics Cards** — Four key metrics displayed prominently:
   - Total ARP events captured
   - Total alerts raised
   - Number of quarantined hosts
   - Detection time (seconds from attack to first alert)

3. **ARP Binding Table** — A real-time table showing all IP-to-MAC bindings with status badges (trusted, normal, changed, quarantined), change counts, VLAN assignments, and last-seen timestamps.

4. **Alert Feed** — A scrolling feed of the 20 most recent detection alerts with severity badges (CRITICAL, HIGH, MEDIUM), detection type, description, source MAC/IP, and MITRE technique references.

5. **Attack Timeline** — A chronological timeline of alerts and quarantine actions with colour-coded dots (critical = red, warning = yellow, quarantine = purple).

6. **Quarantine Feed** — Detailed quarantine action cards showing status (✅ applied, ❌ failed), port, MAC, VLAN transition, method used, and timestamp.

7. **MITRE ATT&CK Panel** — Displays the technique ID, name, tactic, data sources, and a list of mitigations.

### 11.2 Dashboard Server

The dashboard server (available in both Node.js and Python) serves two purposes:

- **Static file server:** Serves `index.html`, `style.css`, and `app.js` on port 8080.
- **API proxy:** Forwards all `/api/*` requests to the Python ARP Guardian REST API on port 8081, enabling same-origin API access from the browser.

### 11.3 Polling Architecture

The frontend JavaScript polls all API endpoints every 2 seconds using `Promise.all()` for parallel requests. The UI updates are orchestrated by a central `updateUI()` function that dispatches to individual component renderers.

---

## 12. Docker Deployment

### 12.1 Docker Compose Configuration

The `docker-compose.yml` creates a fully isolated Docker bridge network (`10.254.254.0/24`) with five containers:

| Container       | IP Address      | Image/Build     | Capabilities  | Purpose              |
|-----------------|-----------------|-----------------|---------------|----------------------|
| `arp-switch`    | 10.254.254.2    | Dockerfile.switch | —            | Simulated switch API |
| `arp-gateway`   | 10.254.254.1    | alpine:3.19     | NET_ADMIN     | Default gateway      |
| `arp-workstation`| 10.254.254.10  | alpine:3.19     | —             | Victim workstation   |
| `arp-attacker`  | 10.254.254.30   | Dockerfile.attacker | NET_RAW, NET_ADMIN | ARP spoofer    |
| `arp-monitor`   | 10.254.254.50   | Dockerfile.monitor | NET_RAW, NET_ADMIN | ARP Guardian     |

### 12.2 Dockerfiles

- **Dockerfile.monitor:** Based on Python 3.12-slim, installs requirements.txt, copies the `src/` directory, and runs `python -m src.arp_guardian` with live capture on `eth0`.
- **Dockerfile.attacker:** Based on Python 3.12-slim, installs scapy, copies the `attacker/` directory. Sits idle until the attack is manually triggered.
- **Dockerfile.switch:** Based on Python 3.12-slim, installs Flask, copies `switch_simulator/`, and runs the Flask app on port 5000.

### 12.3 Usage

The local Dockerfiles in the project folder are sufficient. No images need to be pushed to Docker Hub or any external registry. Docker reads the Dockerfiles directly from the project directory when you run:

```bash
docker-compose up --build -d
```

Docker builds the images locally on your machine and starts the containers in the isolated network.

---

## 13. Testing Strategy

### 13.1 Unit Tests

Three test modules are provided using `pytest`:

1. **`test_arp_cache.py`** — Tests the ARP binding table:
   - Seeding trusted bindings
   - Updating with new and changed MAC addresses
   - Change counting and history tracking
   - Quarantine marking
   - Thread safety

2. **`test_detector.py`** — Tests the threat detection engine:
   - MAC change detection at various severity levels
   - MAC flapping detection with threshold behaviour
   - Gateway impersonation detection
   - Gratuitous ARP flood detection with time windows
   - ARP storm rate limiting
   - Duplicate IP detection

3. **`test_vlan_manager.py`** — Tests the quarantine orchestrator:
   - Port resolution from MAC address
   - VLAN change application
   - Quarantine action recording
   - Release functionality

### 13.2 Running Tests

```bash
python -m pytest tests/ -v --tb=short
```

### 13.3 Wireshark Validation

For live capture mode, ARP traffic can be captured to a pcap file for offline analysis in Wireshark:

```bash
sudo ./scripts/capture_arp.sh eth0 60
wireshark data/arp_capture.pcap
```

Useful Wireshark display filters:
- `arp` — All ARP traffic
- `arp.opcode == 2` — ARP replies only
- `arp.src.hw_mac == aa:bb:cc` — Filter by source MAC
- `arp.duplicate-address-detected` — Duplicate address detection

---

## 14. Threat Model & Risk Assessment

### 14.1 Assets Under Protection

| Asset                  | Description                              | Criticality |
|------------------------|------------------------------------------|-------------|
| Default gateway        | Routes all LAN traffic to external networks | Critical  |
| Workstations           | End-user machines with sensitive data    | High        |
| Servers                | Application and database servers         | High        |
| Network integrity      | Correct IP-to-MAC bindings in ARP caches | Critical   |
| Traffic confidentiality| Data flowing between hosts and gateway   | High        |

### 14.2 Attack Scenarios

**Scenario 1 — Gateway Impersonation (Primary):**  
Attacker sends spoofed ARP reply telling the victim that the gateway's IP is at the attacker's MAC. All outbound traffic from the victim flows through the attacker, enabling credential interception.

**Scenario 2 — Full-Duplex MitM:**  
Attacker poisons both the victim and the gateway, intercepting traffic in both directions. This enables packet modification and injection.

**Scenario 3 — Denial of Service:**  
Attacker sends spoofed ARP replies with a nonexistent MAC, causing the victim to send traffic to a black hole.

### 14.3 Risk Assessment

| Risk                         | Likelihood | Impact | Risk Level   |
|------------------------------|-----------|--------|--------------|
| ARP poisoning by insider     | High      | High   | **Critical** |
| False positive quarantine    | Low       | Medium | **Medium**   |
| Evasion via low-and-slow     | Medium    | Medium | **Medium**   |
| VLAN hopping escape          | Low       | High   | **Medium**   |

---

## 15. Known Limitations & Bypasses

The following limitations are documented for security depth:

1. **Low-and-slow attacks** — An attacker can send spoofed packets below the rate detection threshold, evading the gratuitous flood and ARP storm detectors.

2. **TOFU (Trust On First Use) model** — The first-seen MAC binding is trusted. If the monitor starts after an ARP cache has already been poisoned, the initial spoofed binding will be accepted as legitimate.

3. **VLAN hopping** — An attacker on a misconfigured trunk port can escape the quarantine VLAN via double-tagging (IEEE 802.1Q).

4. **Monitor self-poisoning** — If the monitor's own ARP cache is poisoned before it starts, detection may be delayed or inaccurate.

5. **MAC re-use** — After quarantine release, the attacker can clone the legitimate host's MAC to avoid port-based identification.

6. **Encrypted tunnels** — ARP poisoning is a Layer 2 attack; detection is blind to upper-layer tunnels and does not inspect encrypted traffic content.

---

## 16. Results & Demonstration

### 16.1 Detection Performance

In simulation mode, the system demonstrates:

- **Detection time:** < 1 second from attack initiation (target: < 30 seconds).
- **Alert coverage:** All six heuristics fire during the simulated attack, providing corroborating evidence.
- **Quarantine success:** The attacker MAC is successfully moved to VLAN 999 within seconds of the first CRITICAL alert.

### 16.2 Sample Detection Output

```
╔══════════════════════════════════════════════════════════╗
║           🛡️  ARP GUARDIAN v1.0.0                       ║
║   ARP Spoofing Detection & Network Segmentation        ║
║   MITRE ATT&CK: T1557.002 — ARP Cache Poisoning       ║
╚══════════════════════════════════════════════════════════╝

  Mode:            SIMULATION
  Auto-Quarantine: ON
  Switch Backend:  REST API

📡 Phase 1: Normal ARP traffic
⚔️  Phase 2: ARP spoofing attack begins!
⏱  Attack detected in 0.0s (target: <30s)
🚨 [CRITICAL] mac_change: Gateway MAC changed — ARP cache poisoning indicator
🚨 [CRITICAL] gateway_impersonation: Definitive ARP spoofing indicator
🔒 Auto-quarantine triggered for attacker MAC
✅ QUARANTINED: MAC moved to VLAN 999
🛡️  Phase 3: Post-quarantine monitoring
```

### 16.3 Output Files

| File                           | Content                           |
|--------------------------------|-----------------------------------|
| `data/arp_guardian.log`        | JSON-formatted structured event log |
| `data/alerts.json`            | All detection alerts              |
| `data/quarantine_log.json`    | Quarantine actions and outcomes   |
| `data/final_summary.json`     | Summary statistics on shutdown    |
| `data/arp_capture.pcap`       | Wireshark capture (if applicable) |

---

## 17. Future Scope

1. **Machine Learning-based anomaly detection** — Complement rule-based heuristics with ML models trained on normal ARP traffic patterns to detect novel attack variants.
2. **DHCP Snooping integration** — Build the trusted binding table from DHCP lease records instead of TOFU.
3. **802.1X integration** — Combine VLAN quarantine with port-based network access control.
4. **Multi-switch support** — Extend to monitor and quarantine across multiple switches in a campus network.
5. **Alert notification channels** — Add email, Slack, and SIEM integration for alert dispatch.
6. **IPv6 support** — Extend detection to Neighbor Discovery Protocol (NDP) spoofing attacks.
7. **Dashboard authentication** — Add login and role-based access control for production deployment.
8. **Persistent database** — Replace in-memory storage with SQLite or PostgreSQL for historical analysis.

---

## 18. Conclusion

ARP Guardian successfully demonstrates a complete detection-and-response pipeline for ARP cache poisoning attacks on local area networks. The system achieves sub-second detection times (well within the 30-second target), implements six corroborating detection heuristics, and provides automated VLAN-based network quarantine aligned with the MITRE ATT&CK framework (T1557.002).

The modular architecture supports three deployment modes — live capture, Docker simulation, and pure software simulation — making it suitable for production security monitoring, educational demonstrations, and security research. The live web dashboard provides intuitive real-time visibility into network topology, attack progression, and quarantine status.

While known limitations exist (documented for security depth), the system provides a robust first line of defence against ARP-based man-in-the-middle attacks and can be extended with additional detection methods and integrations in future work.

---

## 19. References

1. MITRE ATT&CK — T1557.002: Adversary-in-the-Middle: ARP Cache Poisoning. https://attack.mitre.org/techniques/T1557/002/
2. RFC 826 — An Ethernet Address Resolution Protocol. D.C. Plummer, November 1982. https://www.rfc-editor.org/rfc/rfc826
3. RFC 5227 — IPv4 Address Conflict Detection. S. Cheshire, July 2008. https://www.rfc-editor.org/rfc/rfc5227
4. Cisco VLAN Membership MIB — SNMP Configuration Guide. https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/45080-vlancfg.html
5. Scapy Documentation — Interactive Packet Manipulation. https://scapy.readthedocs.io/
6. pysnmp Documentation — SNMP library for Python. https://pysnmp.readthedocs.io/
7. Docker Compose Documentation — Multi-container Applications. https://docs.docker.com/compose/

---

*Report generated on 23 May 2026.*
