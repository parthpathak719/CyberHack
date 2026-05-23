"""
Tests for the VLAN Manager quarantine logic.
"""

import pytest
from unittest.mock import MagicMock, patch
from src.arp_guardian.vlan_manager import VlanManager
from src.arp_guardian.models import Alert, QuarantineStatus


class TestVlanManager:
    """Unit tests for VlanManager."""

    def setup_method(self):
        self.mgr = VlanManager(
            use_snmp=False,
            switch_api_url="http://localhost:5000",
            quarantine_vlan=999,
            normal_vlan=1,
            log_file="/tmp/test_quarantine.json",
        )

    def test_quarantine_resolves_known_mac(self):
        """Quarantine should resolve a known MAC from the port map."""
        alert = Alert(
            src_mac="02:42:c0:a8:64:14",
            src_ip="192.168.100.20",
            detection_type="mac_change",
            severity="critical",
        )

        # Mock the switch API call
        with patch.object(self.mgr, '_apply_vlan_change', return_value=True):
            action = self.mgr.quarantine(alert)

        assert action.switch_port == "Gi0/3"
        assert action.status == QuarantineStatus.APPLIED.value
        assert action.to_vlan == 999

    def test_quarantine_unknown_mac_fails(self):
        """Quarantine should fail gracefully for unknown MACs."""
        alert = Alert(
            src_mac="ff:ff:ff:ff:ff:ff",
            src_ip="10.0.0.99",
            detection_type="mac_change",
        )

        action = self.mgr.quarantine(alert)
        assert action.status == QuarantineStatus.FAILED.value

    def test_release_restores_vlan(self):
        """Release should move the port back to the normal VLAN."""
        with patch.object(self.mgr, '_apply_vlan_change', return_value=True):
            action = self.mgr.release("02:42:c0:a8:64:14")

        assert action is not None
        assert action.to_vlan == 1
        assert action.status == QuarantineStatus.RELEASED.value

    def test_get_quarantined_macs(self):
        """Should track which MACs are currently quarantined."""
        alert = Alert(
            src_mac="02:42:c0:a8:64:14",
            src_ip="192.168.100.20",
        )

        with patch.object(self.mgr, '_apply_vlan_change', return_value=True):
            self.mgr.quarantine(alert)

        macs = self.mgr.get_quarantined_macs()
        assert "02:42:c0:a8:64:14" in macs

    def test_get_all_actions(self):
        """Should return all recorded quarantine actions."""
        alert = Alert(
            src_mac="02:42:c0:a8:64:14",
            src_ip="192.168.100.20",
        )

        with patch.object(self.mgr, '_apply_vlan_change', return_value=True):
            self.mgr.quarantine(alert)

        actions = self.mgr.get_all_actions()
        assert len(actions) == 1
        assert actions[0]["attacker_mac"] == "02:42:c0:a8:64:14"
