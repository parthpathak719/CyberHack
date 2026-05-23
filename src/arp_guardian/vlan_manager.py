"""
VLAN Quarantine Manager.

Orchestrates the automated response to detected ARP spoofing:
  1. Receives an alert from the ThreatDetector.
  2. Looks up the attacker's switch port (via switch API or config).
  3. Moves the port to the quarantine VLAN (999).
  4. Records the quarantine action.

Supports two back-ends:
  - Simulated switch REST API  (default, for Docker demo)
  - Real SNMP SET commands     (for production switches)
"""

import json
import os
import threading
from datetime import datetime
from typing import List, Optional

from .models import Alert, QuarantineAction, QuarantineStatus
from .switch_client import SwitchApiClient
from .snmp_client import SnmpClient
from .logger import setup_logger

logger = setup_logger(__name__)


# ── Port mapping: MAC -> (port_name, ifIndex) ─────────────────────
# In a real deployment this comes from the switch's MAC address table.
# For the Docker demo, we pre-map the simulated hosts.
DEFAULT_PORT_MAP = {
    "02:42:c0:a8:64:01": ("Gi0/1", 1),   # Gateway
    "02:42:c0:a8:64:0a": ("Gi0/2", 2),   # Victim / Workstation
    "02:42:c0:a8:64:14": ("Gi0/3", 3),   # Server
    "02:42:c0:a8:64:1e": ("Gi0/4", 4),   # Attacker
    "02:42:c0:a8:64:1f": ("Gi0/6", 6),   # Attacker 2
    "02:42:c0:a8:64:20": ("Gi0/7", 7),   # Attacker 3
    "02:42:c0:a8:64:0b": ("Gi0/8", 8),   # Workstation 2
    "02:42:c0:a8:64:0c": ("Gi0/9", 9),   # Workstation 3
    "02:42:c0:a8:64:15": ("Gi0/10", 10), # Server 2
}


class VlanManager:
    """
    Manages VLAN-based network quarantine of attacking hosts.
    """

    def __init__(
        self,
        use_snmp: bool = False,
        switch_api_url: str = "http://switch-sim:5000",
        snmp_host: str = "192.168.100.1",
        snmp_community: str = "private",
        snmp_port: int = 161,
        quarantine_vlan: int = 999,
        normal_vlan: int = 1,
        log_file: str = "data/quarantine_log.json",
        port_map: Optional[dict] = None,
    ):
        self._use_snmp = use_snmp
        self._quarantine_vlan = quarantine_vlan
        self._normal_vlan = normal_vlan
        self._log_file = log_file
        self._port_map = port_map or DEFAULT_PORT_MAP
        self._lock = threading.Lock()
        self._actions: List[QuarantineAction] = []

        # Initialise the appropriate back-end
        if use_snmp:
            self._snmp = SnmpClient(
                host=snmp_host, port=snmp_port, community=snmp_community
            )
            self._api = None
            logger.info("VLAN Manager: using SNMP back-end")
        else:
            self._api = SwitchApiClient(base_url=switch_api_url)
            self._snmp = None
            logger.info("VLAN Manager: using simulated switch API")

    # ── Quarantine ─────────────────────────────────────────────────

    def quarantine(self, alert: Alert) -> QuarantineAction:
        """
        Quarantine the attacker identified in an alert.

        Steps:
          1. Resolve the attacker MAC to a switch port.
          2. Issue a VLAN change to the quarantine VLAN.
          3. Record the action.

        Returns:
            The QuarantineAction with its outcome status.
        """
        mac = alert.src_mac.lower()
        port_name, if_index = self._resolve_port(mac)

        action = QuarantineAction(
            alert_id=alert.id,
            attacker_mac=mac,
            attacker_ip=alert.src_ip,
            switch_port=port_name,
            from_vlan=self._normal_vlan,
            to_vlan=self._quarantine_vlan,
            method="snmp" if self._use_snmp else "switch_api",
        )

        if not port_name:
            action.status = QuarantineStatus.FAILED.value
            action.error_message = f"Could not resolve port for MAC {mac}"
            logger.error(f"Quarantine FAILED: {action.error_message}")
        else:
            success = self._apply_vlan_change(port_name, if_index, self._quarantine_vlan)
            if success:
                action.status = QuarantineStatus.APPLIED.value
                logger.info(
                    f"✅ QUARANTINED: MAC {mac} (port {port_name}) "
                    f"moved to VLAN {self._quarantine_vlan}"
                )
            else:
                action.status = QuarantineStatus.FAILED.value
                action.error_message = "VLAN change command failed"
                logger.error(
                    f"❌ Quarantine FAILED for MAC {mac} on port {port_name}"
                )

        self._record_action(action)
        return action

    def release(self, mac: str) -> Optional[QuarantineAction]:
        """
        Release a quarantined host back to the normal VLAN.

        Returns:
            A new QuarantineAction with released status, or None.
        """
        mac = mac.lower()
        port_name, if_index = self._resolve_port(mac)

        if not port_name:
            logger.error(f"Cannot release MAC {mac}: port not found")
            return None

        success = self._apply_vlan_change(port_name, if_index, self._normal_vlan)

        action = QuarantineAction(
            attacker_mac=mac,
            switch_port=port_name,
            from_vlan=self._quarantine_vlan,
            to_vlan=self._normal_vlan,
            method="snmp" if self._use_snmp else "switch_api",
            status=(
                QuarantineStatus.RELEASED.value if success
                else QuarantineStatus.FAILED.value
            ),
            released_at=datetime.utcnow().isoformat() + "Z" if success else "",
        )

        self._record_action(action)

        if success:
            logger.info(f"🔓 RELEASED: MAC {mac} back to VLAN {self._normal_vlan}")
        return action

    # ── Internals ──────────────────────────────────────────────────

    def _resolve_port(self, mac: str) -> tuple:
        """
        Resolve a MAC address to a (port_name, ifIndex) tuple.

        Tries the switch API first, then falls back to the static map.
        """
        # Try dynamic lookup via switch API
        if self._api:
            port = self._api.get_port_for_mac(mac)
            if port:
                # Find ifIndex from port_map
                for m, (p, idx) in self._port_map.items():
                    if p == port:
                        return (port, idx)
                return (port, 0)

        # Fall back to static port map
        if mac in self._port_map:
            return self._port_map[mac]

        return (None, 0)

    def _apply_vlan_change(
        self, port_name: str, if_index: int, vlan_id: int
    ) -> bool:
        """Apply a VLAN change via the configured back-end."""
        if self._use_snmp and self._snmp:
            return self._snmp.set_port_vlan(if_index, vlan_id)
        elif self._api:
            return self._api.set_port_vlan(port_name, vlan_id)
        else:
            logger.error("No switch back-end available")
            return False

    def _record_action(self, action: QuarantineAction) -> None:
        """Persist the quarantine action to the log file and memory."""
        with self._lock:
            self._actions.append(action)

        # Append to JSON log file
        os.makedirs(os.path.dirname(self._log_file) or ".", exist_ok=True)
        try:
            existing = []
            if os.path.exists(self._log_file):
                with open(self._log_file, "r") as f:
                    existing = json.load(f)
            existing.append(action.to_dict())
            with open(self._log_file, "w") as f:
                json.dump(existing, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write quarantine log: {e}")

    # ── Queries ────────────────────────────────────────────────────

    def get_all_actions(self) -> List[dict]:
        """Return all quarantine actions."""
        with self._lock:
            return [a.to_dict() for a in self._actions]

    def get_quarantined_macs(self) -> List[str]:
        """Return MACs currently quarantined."""
        with self._lock:
            quarantined = set()
            for a in self._actions:
                if a.status == QuarantineStatus.APPLIED.value:
                    quarantined.add(a.attacker_mac)
                elif a.status == QuarantineStatus.RELEASED.value:
                    quarantined.discard(a.attacker_mac)
            return list(quarantined)
