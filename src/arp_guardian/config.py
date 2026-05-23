"""
Configuration management for ARP Guardian.

Loads settings from environment variables with sensible defaults for
both Docker-based and local simulation deployment modes.
"""

import os
from dataclasses import dataclass


@dataclass
class Config:
    """Central configuration for the ARP Guardian system."""

    # ── Network Interface ──────────────────────────────────────────
    interface: str = "eth0"

    # ── Detection Tuning ───────────────────────────────────────────
    detection_window_sec: int = 30      # Max time to detect spoofing
    mac_change_threshold: int = 2       # MAC changes before flagging
    gratuitous_arp_threshold: int = 5   # Gratuitous ARPs/min to flag
    arp_rate_threshold: int = 50        # ARP packets/min from one MAC
    cache_ttl_sec: int = 300            # Trusted binding TTL

    # ── Switch Connection ──────────────────────────────────────────
    switch_api_url: str = "http://switch-sim:5000"
    switch_snmp_host: str = "192.168.100.1"
    switch_snmp_community: str = "private"
    switch_snmp_port: int = 161

    # ── VLAN Settings ──────────────────────────────────────────────
    quarantine_vlan_id: int = 999
    normal_vlan_id: int = 1

    # ── Logging & Data ─────────────────────────────────────────────
    log_level: str = "INFO"
    log_file: str = "data/arp_guardian.log"
    event_log_file: str = "data/arp_events.json"
    quarantine_log_file: str = "data/quarantine_log.json"
    alert_log_file: str = "data/alerts.json"

    # ── Dashboard / API ────────────────────────────────────────────
    dashboard_port: int = 8080
    api_port: int = 8081

    # ── Operating Mode ─────────────────────────────────────────────
    simulation_mode: bool = False       # True = synthetic traffic
    use_snmp: bool = False              # True = real SNMP, False = REST API
    auto_quarantine: bool = True        # Auto-isolate attackers

    # ── Trusted Hosts (seed the ARP cache) ─────────────────────────
    gateway_ip: str = "192.168.100.1"
    gateway_mac: str = "02:42:c0:a8:64:01"

    @classmethod
    def from_env(cls) -> "Config":
        """Build configuration from environment variables."""
        return cls(
            interface=os.getenv("ARP_IFACE", "eth0"),
            detection_window_sec=int(os.getenv("DETECT_WINDOW", "30")),
            mac_change_threshold=int(os.getenv("MAC_CHANGE_THRESH", "2")),
            gratuitous_arp_threshold=int(os.getenv("GRAT_ARP_THRESH", "5")),
            arp_rate_threshold=int(os.getenv("ARP_RATE_THRESH", "50")),
            cache_ttl_sec=int(os.getenv("CACHE_TTL", "300")),
            switch_api_url=os.getenv("SWITCH_API_URL", "http://switch-sim:5000"),
            switch_snmp_host=os.getenv("SWITCH_SNMP_HOST", "192.168.100.1"),
            switch_snmp_community=os.getenv("SWITCH_SNMP_COMMUNITY", "private"),
            switch_snmp_port=int(os.getenv("SWITCH_SNMP_PORT", "161")),
            quarantine_vlan_id=int(os.getenv("QUARANTINE_VLAN", "999")),
            normal_vlan_id=int(os.getenv("NORMAL_VLAN", "1")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            simulation_mode=os.getenv("SIMULATION_MODE", "").lower() in ("1", "true", "yes"),
            use_snmp=os.getenv("USE_SNMP", "").lower() in ("1", "true", "yes"),
            auto_quarantine=os.getenv("AUTO_QUARANTINE", "true").lower() in ("1", "true", "yes"),
            gateway_ip=os.getenv("GATEWAY_IP", "192.168.100.1"),
            gateway_mac=os.getenv("GATEWAY_MAC", "02:42:c0:a8:64:01"),
        )
