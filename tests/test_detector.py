"""
Tests for the Threat Detector engine.
"""

import pytest
from src.arp_guardian.arp_cache import ArpCache
from src.arp_guardian.detector import ThreatDetector
from src.arp_guardian.models import ArpEvent, DetectionType, Severity


class TestThreatDetector:
    """Unit tests for ThreatDetector."""

    def setup_method(self):
        self.cache = ArpCache()
        self.cache.seed("192.168.100.1", "02:42:c0:a8:64:01", is_trusted=True)
        self.detector = ThreatDetector(
            cache=self.cache,
            gateway_ip="192.168.100.1",
            gateway_mac="02:42:c0:a8:64:01",
            mac_change_threshold=2,
            gratuitous_threshold=3,
            rate_threshold=100,
        )

    def test_normal_traffic_no_alerts(self):
        """Normal ARP reply from a known host should not trigger alerts."""
        event = ArpEvent(
            src_mac="02:42:c0:a8:64:01",
            src_ip="192.168.100.1",
            dst_ip="192.168.100.10",
            operation=2,
        )
        alerts = self.detector.analyze(event)
        assert len(alerts) == 0

    def test_mac_change_triggers_alert(self):
        """A MAC change on a known IP should trigger a MAC_CHANGE alert."""
        # First: legitimate traffic from workstation
        e1 = ArpEvent(src_mac="02:42:c0:a8:64:0a", src_ip="192.168.100.10")
        self.detector.analyze(e1)

        # Second: spoofed reply claiming same IP but different MAC
        e2 = ArpEvent(src_mac="de:ad:be:ef:00:01", src_ip="192.168.100.10")
        alerts = self.detector.analyze(e2)

        assert len(alerts) >= 1
        assert any(a.detection_type == DetectionType.MAC_CHANGE.value for a in alerts)

    def test_gateway_impersonation_critical(self):
        """Someone claiming to be the gateway with wrong MAC is CRITICAL."""
        event = ArpEvent(
            src_mac="de:ad:be:ef:00:01",  # Not the real gateway MAC
            src_ip="192.168.100.1",        # Claiming gateway IP
            dst_ip="192.168.100.10",
            operation=2,
        )
        alerts = self.detector.analyze(event)

        gateway_alerts = [
            a for a in alerts
            if a.detection_type == DetectionType.GATEWAY_IMPERSONATION.value
        ]
        assert len(gateway_alerts) >= 1
        assert gateway_alerts[0].severity == Severity.CRITICAL.value

    def test_mac_flap_after_threshold(self):
        """Multiple MAC changes should trigger MAC_FLAP alert."""
        # Establish initial binding
        e1 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.100.10")
        self.detector.analyze(e1)

        # Change 1
        e2 = ArpEvent(src_mac="11:22:33:44:55:66", src_ip="192.168.100.10")
        self.detector.analyze(e2)

        # Change 2 (threshold = 2)
        e3 = ArpEvent(src_mac="de:ad:be:ef:00:01", src_ip="192.168.100.10")
        alerts = self.detector.analyze(e3)

        flap_alerts = [
            a for a in alerts
            if a.detection_type == DetectionType.MAC_FLAP.value
        ]
        assert len(flap_alerts) >= 1

    def test_gratuitous_flood_detection(self):
        """Excessive gratuitous ARPs should trigger an alert."""
        for i in range(5):
            event = ArpEvent(
                src_mac="de:ad:be:ef:00:01",
                src_ip="192.168.100.30",
                dst_ip="192.168.100.30",
                operation=2,
                is_gratuitous=True,
            )
            alerts = self.detector.analyze(event)

        # At threshold=3, we should have at least one GRATUITOUS_FLOOD alert
        flood_alerts = [
            a for a in self.detector.get_all_alerts()
            if a["detection_type"] == DetectionType.GRATUITOUS_FLOOD.value
        ]
        assert len(flood_alerts) >= 1

    def test_detection_stats(self):
        """Stats should reflect the number and types of alerts."""
        # Generate a MAC change alert
        e1 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.100.10")
        self.detector.analyze(e1)
        e2 = ArpEvent(src_mac="11:22:33:44:55:66", src_ip="192.168.100.10")
        self.detector.analyze(e2)

        stats = self.detector.get_detection_stats()
        assert stats["total_alerts"] >= 1
        assert DetectionType.MAC_CHANGE.value in stats["by_type"]

    def test_auto_response_on_gateway_attack(self):
        """Gateway impersonation should set auto_response=True."""
        event = ArpEvent(
            src_mac="de:ad:be:ef:00:01",
            src_ip="192.168.100.1",
            operation=2,
        )
        alerts = self.detector.analyze(event)
        auto_alerts = [a for a in alerts if a.auto_response]
        assert len(auto_alerts) >= 1

    def test_mitre_mapping_in_alerts(self):
        """All alerts should reference the ATT&CK technique."""
        e1 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.100.10")
        self.detector.analyze(e1)
        e2 = ArpEvent(src_mac="11:22:33:44:55:66", src_ip="192.168.100.10")
        alerts = self.detector.analyze(e2)

        for alert in alerts:
            assert alert.mitre_technique == "T1557.002"
