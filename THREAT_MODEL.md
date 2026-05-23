# Threat Model — ARP Cache Poisoning (T1557.002)

## Overview

This document provides a structured threat model for ARP cache poisoning attacks on an on-premises LAN, aligning with MITRE ATT&CK technique T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning).

## 1. System Description

### Assets Under Protection

| Asset | Description | Criticality |
| --- | --- | --- |
| Default gateway | Routes all LAN traffic to external networks | Critical |
| Workstations | End-user machines with sensitive data | High |
| Servers | Application and database servers | High |
| Network integrity | Correct IP-to-MAC bindings in ARP caches | Critical |
| Traffic confidentiality | Data flowing between hosts and gateway | High |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│                External Network (WAN)                │
└────────────────────────┬────────────────────────────┘
                         │ Trust Boundary 1
                    ┌────┴────┐
                    │ Gateway │  (Firewall/Router)
                    └────┬────┘
                         │ Trust Boundary 2
    ═══════════════════╪════════════════════════════
    │            LAN (Layer 2 broadcast domain)    │
    │                                              │
    │   Workstation   Server   Printer   Attacker  │
    │       ↕           ↕        ↕          ↕      │
    │        Shared Ethernet / WiFi Segment        │
    ═══════════════════════════════════════════════
```

### Threat: ARP Cache Poisoning

ARP operates at Layer 2 and is stateless — hosts accept ARP replies without verifying that they sent a corresponding request. An attacker exploits this by sending forged ARP replies to:

1. **Tell the victim** that the gateway's IP is at the attacker's MAC
2. **Tell the gateway** that the victim's IP is at the attacker's MAC

This positions the attacker as a man-in-the-middle (MitM).

## 2. MITRE ATT&CK Mapping

| Field | Value |
| --- | --- |
| **Technique ID** | T1557.002 |
| **Technique Name** | Adversary-in-the-Middle: ARP Cache Poisoning |
| **Tactic** | Credential Access (TA0006), Collection (TA0009) |
| **Platform** | Linux, macOS, Windows |
| **Permissions** | User (raw socket / admin on Windows) |
| **Data Sources** | DS0029: Network Traffic (Content + Flow) |

### Sub-technique Context

T1557.002 is a sub-technique of T1557 (Adversary-in-the-Middle). Related sub-techniques include:

- T1557.001 — LLMNR/NBT-NS Poisoning
- T1557.003 — DHCP Spoofing

### Attack Kill Chain Position

```
Reconnaissance → Initial Access → Execution → Persistence →
Privilege Escalation → Defence Evasion → ★ Credential Access ★ →
Discovery → Lateral Movement → Collection → Exfiltration
```

ARP poisoning sits at the **Credential Access** stage, enabling the attacker to intercept plaintext credentials, session tokens, and API keys flowing through the network.

## 3. Attack Scenarios

### Scenario 1: Gateway Impersonation (Primary)

**Goal:** Intercept all outbound traffic from a workstation.

1. Attacker sends spoofed ARP reply to victim: "192.168.100.1 is at `attacker_mac`"
2. Victim's ARP cache is poisoned: traffic to gateway goes to attacker instead
3. Attacker forwards traffic to real gateway (transparent MitM)
4. Attacker captures credentials, HTTP sessions, DNS queries

**Indicators:**
- Gateway IP bound to non-gateway MAC in victim's ARP cache
- Multiple MACs claiming the same IP
- Unusual ARP reply rate from attacker MAC

### Scenario 2: Full-Duplex MitM

**Goal:** Intercept traffic in both directions.

1. Attacker poisons both victim and gateway
2. All traffic between them flows through attacker
3. Attacker can modify packets in transit (injection)

### Scenario 3: Denial of Service

**Goal:** Disrupt network connectivity.

1. Attacker sends spoofed ARP replies with a nonexistent MAC
2. Victim sends traffic to a black hole
3. Effective DoS without flooding the network

## 4. Detection Strategy

### 4.1 ARP Cache Monitoring (Implemented)

| Check | Description | Confidence |
| --- | --- | --- |
| MAC binding change | IP's MAC changed from known-good baseline | High |
| MAC flapping | Rapid MAC oscillation (≥2 changes) | Very High |
| Gateway impersonation | Non-gateway MAC claiming gateway IP | Very High |
| Gratuitous ARP flood | ≥5 unsolicited ARPs per minute | Medium |
| ARP storm | ≥50 ARP packets per minute from one MAC | Medium |
| Duplicate IP | Same IP from two different MACs | High |

### 4.2 Detection Timeline Requirement

The system must detect ARP spoofing within **30 seconds** of attack initiation. This is achieved by:

- Continuous passive ARP sniffing (no polling interval)
- Immediate comparison against the trusted binding table
- Parallel heuristic evaluation for each packet

### 4.3 Data Sources (per ATT&CK DS0029)

- **Network Traffic Content** — ARP packet fields (op, hwsrc, psrc, hwdst, pdst)
- **Network Traffic Flow** — ARP packet rate per source MAC

## 5. Response Strategy

### 5.1 Automated VLAN Quarantine (Implemented)

When an attack is confirmed:

1. **Identify** attacker MAC from spoofed ARP reply
2. **Resolve** MAC to switch port (via MAC address table lookup)
3. **Isolate** by moving the port to VLAN 999 (quarantine)
4. **Log** the quarantine action with timestamp and evidence

### 5.2 VLAN Change Mechanisms

| Method | OID / Endpoint | Use Case |
| --- | --- | --- |
| SNMP SET (Cisco) | `1.3.6.1.4.1.9.9.68.1.2.2.1.2.<ifIndex>` | Real Cisco switches |
| SNMP SET (Generic) | `1.3.6.1.2.1.17.7.1.4.5.1.1.<port>` | Q-BRIDGE compliant switches |
| REST API | `POST /api/port/vlan` | Simulated switch (demo) |

### 5.3 Limitations of Quarantine

- **Collateral damage** — Legitimate traffic from the quarantined port is also blocked
- **VLAN hopping** — If trunk ports are misconfigured, attacker may escape
- **MAC spoofing** — Attacker can change MAC to evade port-based quarantine
- **Timing window** — A few seconds of spoofed traffic may pass before quarantine

## 6. Mitigations (per MITRE)

| ID | Mitigation | Implementation |
| --- | --- | --- |
| M1037 | Filter Network Traffic | VLAN quarantine isolates attacker |
| M1035 | Limit Access to Resource Over Network | 802.1X port authentication |
| M1031 | Network Intrusion Prevention | ARP Guardian continuous monitoring |
| M1017 | User Training | Awareness of insider threat risks |

### Additional Mitigations (Beyond Scope)

- **Dynamic ARP Inspection (DAI)** on managed switches
- **DHCP Snooping** to build trusted IP-MAC bindings
- **802.1X** port-based network access control
- **Static ARP entries** for critical hosts (gateway)
- **Encrypted protocols** (TLS, SSH) to mitigate data exposure even if MitM succeeds

## 7. Risk Assessment

| Risk | Likelihood | Impact | Risk Level |
| --- | --- | --- | --- |
| ARP poisoning by insider | High (trivial with tools like `arpspoof`) | High (credential theft, data exfiltration) | **Critical** |
| False positive quarantine | Low (with trusted baseline + threshold) | Medium (temporary connectivity loss) | **Medium** |
| Evasion via low-and-slow | Medium (below detection threshold) | Medium (delayed detection) | **Medium** |
| VLAN hopping escape | Low (requires trunk misconfiguration) | High (quarantine bypass) | **Medium** |

## 8. References

- [MITRE ATT&CK T1557.002](https://attack.mitre.org/techniques/T1557/002/)
- [RFC 826 — ARP Protocol](https://www.rfc-editor.org/rfc/rfc826)
- [RFC 5227 — IPv4 Address Conflict Detection](https://www.rfc-editor.org/rfc/rfc5227)
- [Cisco VLAN Membership MIB](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/45080-vlancfg.html)
