"""
Data models for ARP Guardian.

Defines structured types for ARP events, detection alerts, quarantine
actions, and MITRE ATT&CK technique mapping.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional
import json
import uuid


class Severity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ArpOperation(Enum):
    """ARP operation types."""
    REQUEST = 1       # who-has
    REPLY = 2         # is-at
    GRATUITOUS = 3    # unsolicited announcement


class DetectionType(Enum):
    """Types of ARP anomalies detected."""
    MAC_CHANGE = "mac_change"                   # IP changed MAC binding
    MAC_FLAP = "mac_flap"                       # Rapid MAC oscillation
    GRATUITOUS_FLOOD = "gratuitous_flood"        # Excessive gratuitous ARPs
    GATEWAY_IMPERSONATION = "gateway_impersonation"  # Gateway MAC spoofed
    DUPLICATE_IP = "duplicate_ip"               # Same IP, two MACs
    ARP_STORM = "arp_storm"                     # Rate-limit exceeded
    UNICAST_REPLY = "unicast_reply"             # Reply to non-requester


class QuarantineStatus(Enum):
    """Quarantine action outcomes."""
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    RELEASED = "released"


# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────

@dataclass
class MitreMapping:
    """MITRE ATT&CK technique reference."""
    technique_id: str = "T1557.002"
    technique_name: str = "Adversary-in-the-Middle: ARP Cache Poisoning"
    tactic: str = "Credential Access / Collection"
    data_sources: tuple = (
        "DS0029: Network Traffic (Network Traffic Content, Network Traffic Flow)",
    )
    mitigations: tuple = (
        "M1037: Filter Network Traffic",
        "M1035: Limit Access to Resource Over Network",
        "M1031: Network Intrusion Prevention",
        "M1017: User Training",
    )
    detection_notes: str = (
        "Monitor for changes in ARP cache entries. Detect gratuitous ARP "
        "replies or unsolicited ARP responses. Compare observed MAC-to-IP "
        "bindings against known-good baselines."
    )

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "data_sources": list(self.data_sources),
            "mitigations": list(self.mitigations),
            "detection_notes": self.detection_notes,
        }


ATTACK_MAPPING = MitreMapping()


# ── Core Data Models ──────────────────────────────────────────────────

@dataclass
class ArpEntry:
    """A single entry in the ARP binding table."""
    ip: str
    mac: str
    first_seen: str = ""
    last_seen: str = ""
    vlan_id: int = 1
    port: str = ""
    is_trusted: bool = False
    change_count: int = 0

    def __post_init__(self):
        now = datetime.utcnow().isoformat() + "Z"
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now


@dataclass
class ArpEvent:
    """A captured ARP packet event."""
    id: str = ""
    timestamp: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    operation: int = 2          # 1=request, 2=reply
    is_gratuitous: bool = False
    raw_summary: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"


@dataclass
class Alert:
    """A detection alert raised by the threat detector."""
    id: str = ""
    timestamp: str = ""
    severity: str = Severity.HIGH.value
    detection_type: str = ""
    description: str = ""
    src_mac: str = ""
    src_ip: str = ""
    target_ip: str = ""
    previous_mac: str = ""
    mitre_technique: str = ATTACK_MAPPING.technique_id
    mitre_tactic: str = ATTACK_MAPPING.tactic
    recommended_action: str = "Quarantine attacker via VLAN isolation"
    auto_response: bool = False

    def __post_init__(self):
        if not self.id:
            self.id = "ALERT-" + str(uuid.uuid4())[:8].upper()
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class QuarantineAction:
    """A VLAN quarantine action applied to an attacker."""
    id: str = ""
    timestamp: str = ""
    alert_id: str = ""
    attacker_mac: str = ""
    attacker_ip: str = ""
    switch_port: str = ""
    from_vlan: int = 1
    to_vlan: int = 999
    method: str = "switch_api"    # "switch_api" or "snmp"
    status: str = QuarantineStatus.PENDING.value
    error_message: str = ""
    released_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = "QUAR-" + str(uuid.uuid4())[:8].upper()
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkHost:
    """A host on the monitored network."""
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    vlan_id: int = 1
    port: str = ""
    role: str = "workstation"    # gateway, workstation, server, unknown
    is_quarantined: bool = False
    last_activity: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
