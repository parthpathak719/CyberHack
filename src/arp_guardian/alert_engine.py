"""
Alert Engine for ARP Guardian.

Centralises alert processing, persistence, and dispatch.
Connects the ThreatDetector output to the VlanManager response
and writes alert data for the dashboard API.
"""

import json
import os
import threading
from typing import List, Optional, Callable

from .models import Alert
from .vlan_manager import VlanManager
from .logger import setup_logger

logger = setup_logger(__name__)


class AlertEngine:
    """
    Processes detection alerts and triggers automated responses.

    Pipeline:
      ThreatDetector -> AlertEngine -> VlanManager (quarantine)
                                   -> JSON log file
                                   -> Dashboard API
    """

    def __init__(
        self,
        vlan_manager: VlanManager,
        auto_quarantine: bool = True,
        alert_log_file: str = "data/alerts.json",
        on_quarantine: Optional[Callable] = None,
    ):
        self._vlan_mgr = vlan_manager
        self._auto_quarantine = auto_quarantine
        self._log_file = alert_log_file
        self._on_quarantine = on_quarantine
        self._lock = threading.Lock()
        self._alerts: List[Alert] = []
        self._quarantined_macs: set = set()

    def process_alert(self, alert: Alert) -> None:
        """
        Handle a new detection alert.

        1. Store the alert.
        2. If auto_quarantine is enabled and the alert recommends it,
           trigger a VLAN quarantine.
        3. Persist to disk.
        """
        with self._lock:
            self._alerts.append(alert)

        # Write to log file
        self._persist_alert(alert)

        # Auto-quarantine if enabled and recommended
        if (
            self._auto_quarantine
            and alert.auto_response
            and alert.src_mac
            and alert.src_mac.lower() not in self._quarantined_macs
        ):
            logger.info(
                f"🔒 Auto-quarantine triggered for {alert.src_mac} "
                f"({alert.src_ip}) — {alert.detection_type}"
            )
            action = self._vlan_mgr.quarantine(alert)
            alert.auto_response = True

            if action.status == "applied":
                self._quarantined_macs.add(alert.src_mac.lower())

            if self._on_quarantine:
                self._on_quarantine(action)

    def _persist_alert(self, alert: Alert) -> None:
        """Append alert to the JSON log file."""
        os.makedirs(os.path.dirname(self._log_file) or ".", exist_ok=True)
        try:
            existing = []
            if os.path.exists(self._log_file):
                with open(self._log_file, "r") as f:
                    existing = json.load(f)
            existing.append(alert.to_dict())
            with open(self._log_file, "w") as f:
                json.dump(existing, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to write alert log: {e}")

    def get_alerts(self) -> List[dict]:
        """Return all alerts."""
        with self._lock:
            return [a.to_dict() for a in self._alerts]

    def get_summary(self) -> dict:
        """Return a summary for the dashboard."""
        with self._lock:
            return {
                "total_alerts": len(self._alerts),
                "quarantined_hosts": len(self._quarantined_macs),
                "auto_quarantine_enabled": self._auto_quarantine,
                "quarantined_macs": list(self._quarantined_macs),
            }
