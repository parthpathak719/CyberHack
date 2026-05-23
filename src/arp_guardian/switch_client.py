"""
Simulated Switch REST API Client.

Communicates with the switch_simulator Flask application to:
  - Query the MAC address table
  - Look up which port a MAC is on
  - Move a port to the quarantine VLAN
  - Release a port back to the normal VLAN

This is the primary quarantine mechanism when USE_SNMP=false.
"""

import json
from typing import Optional

from .logger import setup_logger

logger = setup_logger(__name__)

# requests is optional — import with fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests library not available. Switch API client disabled.")


class SwitchApiClient:
    """REST client for the simulated managed switch."""

    def __init__(self, base_url: str = "http://switch-sim:5000"):
        self._base_url = base_url.rstrip("/")

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    # ── Port Operations ────────────────────────────────────────────

    def get_port_for_mac(self, mac: str) -> Optional[str]:
        """Look up which port a MAC address is connected to."""
        if not REQUESTS_AVAILABLE:
            return None
        try:
            resp = requests.get(
                self._url("/api/mac-table"),
                params={"mac": mac.lower()},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("port")
        except Exception as e:
            logger.error(f"Failed to look up port for MAC {mac}: {e}")
            return None

    def set_port_vlan(self, port: str, vlan_id: int) -> bool:
        """
        Move a switch port to a specific VLAN.

        Args:
            port: Switch port identifier (e.g., "Gi0/3").
            vlan_id: Target VLAN ID.

        Returns:
            True if the operation succeeded.
        """
        if not REQUESTS_AVAILABLE:
            return False
        try:
            resp = requests.post(
                self._url("/api/port/vlan"),
                json={"port": port, "vlan_id": vlan_id},
                timeout=5,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                f"Switch API: port {port} moved to VLAN {vlan_id} — "
                f"{result.get('status', 'ok')}"
            )
            return result.get("success", False)
        except Exception as e:
            logger.error(f"Failed to set VLAN for port {port}: {e}")
            return False

    def get_port_status(self, port: str) -> Optional[dict]:
        """Get the current status of a switch port."""
        if not REQUESTS_AVAILABLE:
            return None
        try:
            resp = requests.get(
                self._url(f"/api/port/{port}"),
                timeout=5,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to get port status for {port}: {e}")
            return None

    def get_mac_table(self) -> list:
        """Retrieve the full MAC address table from the switch."""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            resp = requests.get(self._url("/api/mac-table"), timeout=5)
            resp.raise_for_status()
            return resp.json().get("entries", [])
        except Exception as e:
            logger.error(f"Failed to get MAC table: {e}")
            return []

    def get_vlan_info(self) -> list:
        """Retrieve VLAN configuration from the switch."""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            resp = requests.get(self._url("/api/vlans"), timeout=5)
            resp.raise_for_status()
            return resp.json().get("vlans", [])
        except Exception as e:
            logger.error(f"Failed to get VLAN info: {e}")
            return []

    def health_check(self) -> bool:
        """Check if the switch simulator is reachable."""
        if not REQUESTS_AVAILABLE:
            return False
        try:
            resp = requests.get(self._url("/api/health"), timeout=3)
            return resp.status_code == 200
        except Exception:
            return False
