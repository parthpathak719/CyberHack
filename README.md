# ARP Guardian — ARP Spoofing Detection & Automated Network Segmentation

A continuous ARP watch daemon that detects ARP cache poisoning attacks on a LAN, identifies the attacking host within 30 seconds, and automatically pushes VLAN isolation rules to quarantine the attacker on a managed switch.

**MITRE ATT&CK:** T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning  
**Architecture:** On-Premises  
**Difficulty:** Medium

---

## Problem Statement

An insider threat is performing ARP cache poisoning attacks on the LAN to intercept traffic between workstations and the default gateway. This project builds a continuous ARP watch daemon that:

1. **Detects** IP-to-MAC binding changes (spoofed ARP replies)
2. **Identifies** the attacking host's MAC address
3. **Quarantines** the attacker by pushing a VLAN isolation rule to a managed switch (simulated via REST API or real via SNMP)

## What It Does

- **Real-time ARP monitoring** using scapy packet capture
- **Multi-heuristic threat detection**: MAC change, MAC flapping, gateway impersonation, gratuitous ARP flood, ARP storm, duplicate IP
- **Automated quarantine** via VLAN isolation (SNMP `vmVlan` SET or simulated switch API)
- **Sub-30-second detection** from attack initiation to first alert
- **MITRE ATT&CK T1557.002** alignment with documented data sources and mitigations
- **Docker-based isolated LAN simulation** for safe, repeatable demos
- **Live web dashboard** with network topology, alert feed, and quarantine status
- **Wireshark validation** support via pcap capture

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    On-Premises LAN (192.168.100.0/24)           │
│                                                                 │
│   ┌──────────┐   ┌────────────┐   ┌──────────┐   ┌──────────┐ │
│   │ Gateway  │   │ Workstation│   │  Server  │   │ Attacker │ │
│   │ .100.1   │   │   .100.10  │   │  .100.20 │   │  .100.30 │ │
│   └────┬─────┘   └─────┬──────┘   └────┬─────┘   └────┬─────┘ │
│        │               │               │               │       │
│   ═════╪═══════════════╪═══════════════╪═══════════════╪═══    │
│        │          Managed Switch (Simulated)            │       │
│        │          VLAN 1 (normal) / VLAN 999 (quarantine)      │
│   ═════╪═══════════════════════════════════════════════════════  │
│        │                                                        │
│   ┌────┴─────────────────────────────────────────┐              │
│   │            ARP Guardian Monitor              │              │
│   │  ┌────────┐  ┌──────────┐  ┌─────────────┐  │              │
│   │  │ Scapy  │→ │ Detector │→ │ VLAN Manager│  │              │
│   │  │Sniffer │  │ (6 rules)│  │ (API/SNMP)  │  │              │
│   │  └────────┘  └──────────┘  └─────────────┘  │              │
│   │              ┌──────────┐                    │              │
│   │              │ REST API │ ← Dashboard        │              │
│   │              └──────────┘                    │              │
│   └──────────────────────────────────────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
| --- | --- |
| ARP capture | Python + scapy |
| SNMP switch control | pysnmp (Cisco vmVlan MIB / Q-BRIDGE) |
| Simulated switch | Flask REST API |
| LAN simulation | Docker + docker-compose |
| Packet validation | Wireshark / tcpdump |
| Dashboard server | Node.js |
| Dashboard frontend | HTML + CSS + Canvas JS |

## Quick Start

### Option 1: Simulation Mode (macOS, no root needed)

```bash
# Install dependencies
pip install -r requirements.txt

# Terminal 1: Start the switch simulator
python switch_simulator/app.py

# Terminal 2: Start ARP Guardian in simulation mode
python -m src.arp_guardian --simulate --switch-url http://localhost:5000

# Terminal 3: Start the dashboard
node dashboard/server.js
```

Then open **http://localhost:8080** to see the live dashboard.

### Option 2: Docker LAN Simulation

```bash
# Build and start the isolated network
docker-compose up --build -d

# Start the dashboard
node dashboard/server.js

# Launch an ARP spoofing attack
docker exec arp-attacker python /app/arp_spoof.py \
  --target 192.168.100.10 --gateway 192.168.100.1 --interface eth0

# Watch the monitor detect and quarantine
docker logs -f arp-monitor
```

### Option 3: One-Command Demo

```bash
chmod +x scripts/run_demo.sh
./scripts/run_demo.sh
```

## Detection Heuristics

| # | Heuristic | Description | Severity |
| --- | --- | --- | --- |
| 1 | MAC Change | IP's MAC binding changed | MEDIUM–HIGH |
| 2 | MAC Flapping | Rapid MAC oscillation (≥2 changes) | CRITICAL |
| 3 | Gateway Impersonation | Non-gateway MAC claiming gateway IP | CRITICAL |
| 4 | Gratuitous ARP Flood | Excessive unsolicited ARPs (≥5/min) | HIGH |
| 5 | ARP Storm | Rate limit exceeded from single MAC | MEDIUM |
| 6 | Duplicate IP | Same IP advertised by two MACs | HIGH |

## MITRE ATT&CK Mapping

- **Technique:** T1557.002 — ARP Cache Poisoning
- **Tactic:** Credential Access / Collection
- **Data Sources:** DS0029 — Network Traffic (Content + Flow)
- **Mitigations:** M1037 (Filter Traffic), M1035 (Limit Access), M1031 (IPS), M1017 (Training)

## Known Limitations & Bypasses

1. **Low-and-slow attacks** — Attacker can send spoofed packets below the rate threshold
2. **TOFU model** — First-seen binding is trusted; initial poisoning before monitor starts is invisible
3. **VLAN hopping** — Attacker on a misconfigured trunk port can escape the quarantine VLAN via double-tagging
4. **Monitor self-poisoning** — If the monitor's own ARP cache is poisoned first, detection may be delayed
5. **MAC re-use** — Attacker can clone the legitimate MAC after quarantine release
6. **Encrypted tunnels** — ARP poisoning is a Layer 2 attack; detection is blind to upper-layer tunnels

## Running Tests

```bash
python -m pytest tests/ -v
```

## Project Structure

```
cyber_hack/
├── src/arp_guardian/           # Core Python package
│   ├── __main__.py             # CLI entry point + REST API
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
│   ├── server.js               # Node.js server (proxy + static)
│   ├── index.html              # Dashboard page
│   ├── style.css               # Premium dark theme
│   └── app.js                  # Canvas topology + real-time UI
├── tests/                      # Unit tests
├── scripts/                    # Automation scripts
├── docker-compose.yml          # Isolated LAN simulation
├── Dockerfile.monitor          # Monitor container
├── Dockerfile.attacker         # Attacker container
├── Dockerfile.switch           # Switch simulator container
├── Makefile                    # Build/run commands
├── requirements.txt            # Python dependencies
├── THREAT_MODEL.md             # Detailed threat model
└── ARCHITECTURE.md             # Architecture documentation
```

## Commands Reference

| Command | Description |
| --- | --- |
| `make simulate` | Run in simulation mode |
| `make live` | Run in live capture (sudo) |
| `make dashboard` | Start dashboard server |
| `make docker` | Build & start Docker containers |
| `make docker-attack` | Launch ARP attack in Docker |
| `make test` | Run unit tests |
| `make clean` | Remove generated files |

## Wireshark Validation

```bash
# Capture ARP traffic
sudo ./scripts/capture_arp.sh eth0 60

# Open in Wireshark
wireshark data/arp_capture.pcap

# Useful display filters:
#   arp                          — All ARP traffic
#   arp.opcode == 2              — ARP replies only
#   arp.src.hw_mac == aa:bb:cc   — Filter by source MAC
#   arp.duplicate-address-detected — Duplicate address
```

## Output Files

After running the system:

- `data/arp_guardian.log` — JSON-formatted event log
- `data/alerts.json` — All detection alerts
- `data/quarantine_log.json` — Quarantine actions
- `data/final_summary.json` — Summary on shutdown
- `data/arp_capture.pcap` — Wireshark capture (if run)
