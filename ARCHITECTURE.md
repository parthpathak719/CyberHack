# Architecture — ARP Guardian

## System Architecture

ARP Guardian follows a **pipeline architecture** with four stages:

```
Capture → Detect → Respond → Report
```

### Component Diagram

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

## Data Flow

### 1. Capture Stage

```
Network Interface → scapy sniff (filter="arp") → ArpEvent
```

- The `ArpMonitor` runs in a daemon thread
- Each ARP packet is parsed into an `ArpEvent` dataclass
- Fields extracted: `src_mac`, `dst_mac`, `src_ip`, `dst_ip`, `operation`, `is_gratuitous`

### 2. Detection Stage

```
ArpEvent → ArpCache.update() → ThreatDetector.analyze() → Alert[]
```

- The `ArpCache` maintains IP-to-MAC bindings (thread-safe)
- The `ThreatDetector` runs 6 parallel heuristics on each event
- Detection is synchronous per-packet (no batching delay)

### 3. Response Stage

```
Alert → AlertEngine.process() → VlanManager.quarantine() → SwitchClient
```

- The `AlertEngine` filters alerts and decides whether to auto-quarantine
- The `VlanManager` resolves the attacker MAC to a switch port
- The switch API or SNMP back-end executes the VLAN change

### 4. Report Stage

```
State → REST API → Dashboard (polling every 2s)
```

- An embedded HTTP server serves JSON endpoints
- The browser dashboard polls and renders the real-time state

## Deployment Modes

### Mode 1: Docker Simulation (Primary Demo)

```
docker-compose up → 5 containers on 192.168.100.0/24
├── gateway     (192.168.100.1)   — Alpine router
├── workstation (192.168.100.10)  — Victim
├── attacker    (192.168.100.30)  — ARP spoofer
├── monitor     (192.168.100.50)  — ARP Guardian
└── switch-sim  (192.168.100.2)   — Flask switch API
```

### Mode 2: Simulation (No Docker/Root)

```
python -m src.arp_guardian --simulate
```

- Generates synthetic ARP events (no real network)
- Three phases: normal → attack → post-quarantine
- Ideal for macOS demos without sudo

### Mode 3: Live Capture (Production)

```
sudo python -m src.arp_guardian --iface eth0 --snmp
```

- Real scapy capture on a physical interface
- SNMP SET to a real managed switch
- Requires NET_RAW capability

## Concurrency Model

```
Main Thread
├── API Server Thread (HTTPServer)
├── ARP Monitor Thread (scapy sniff) or Simulator Thread
└── Signal Handler (SIGINT → graceful shutdown)
```

All shared state is protected by `threading.Lock` instances in:
- `ArpCache._lock`
- `ThreatDetector._lock`
- `AlertEngine._lock`
- `VlanManager._lock`

## Security Considerations

| Concern | Mitigation |
| --- | --- |
| Monitor must run as root for raw sockets | Use Docker with `NET_RAW` capability; use simulation mode otherwise |
| SNMP community string exposure | Use SNMP v3 with authentication in production; v2c only for demo |
| Dashboard API has no authentication | Intended for internal use only; add auth for production |
| Switch API has no authentication | Docker-internal only; not exposed to host network |

## On-Premises Architecture Fit

This solution targets **on-premises LAN** environments because:

1. **ARP is Layer 2** — Only meaningful within a broadcast domain
2. **Switch management** — Requires direct access to the managed switch
3. **Network tap** — The monitor must be in the same VLAN as the targets
4. **SNMP access** — SNMP management networks are typically on-premises

Cloud environments use virtual networking where ARP is either abstracted away or handled by the hypervisor (e.g., AWS VPC does not expose ARP to guests).
