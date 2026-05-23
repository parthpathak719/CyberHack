"""
Tests for the ARP cache binding table manager.
"""

import pytest
from src.arp_guardian.arp_cache import ArpCache
from src.arp_guardian.models import ArpEvent


class TestArpCache:
    """Unit tests for ArpCache."""

    def setup_method(self):
        self.cache = ArpCache(cache_ttl_sec=300)

    def test_seed_adds_trusted_entry(self):
        self.cache.seed("192.168.1.1", "aa:bb:cc:dd:ee:ff", is_trusted=True)
        entry = self.cache.get("192.168.1.1")
        assert entry is not None
        assert entry.mac == "aa:bb:cc:dd:ee:ff"
        assert entry.is_trusted is True

    def test_update_new_ip_returns_none(self):
        event = ArpEvent(
            src_mac="aa:bb:cc:dd:ee:ff",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            operation=2,
        )
        result = self.cache.update(event)
        assert result is None
        assert self.cache.size() == 1

    def test_update_same_mac_returns_none(self):
        event1 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.1.10")
        event2 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.1.10")
        self.cache.update(event1)
        result = self.cache.update(event2)
        assert result is None

    def test_update_different_mac_returns_change(self):
        event1 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.1.10")
        event2 = ArpEvent(src_mac="11:22:33:44:55:66", src_ip="192.168.1.10")
        self.cache.update(event1)
        result = self.cache.update(event2)
        assert result is not None
        old_mac, new_mac = result
        assert old_mac == "aa:bb:cc:dd:ee:ff"
        assert new_mac == "11:22:33:44:55:66"

    def test_change_count_increments(self):
        self.cache.seed("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        event = ArpEvent(src_mac="11:22:33:44:55:66", src_ip="192.168.1.1")
        self.cache.update(event)
        assert self.cache.get_change_count("192.168.1.1") == 1

    def test_find_ips_by_mac(self):
        e1 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.1.10")
        e2 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.1.20")
        self.cache.update(e1)
        self.cache.update(e2)
        ips = self.cache.find_ips_by_mac("aa:bb:cc:dd:ee:ff")
        assert "192.168.1.10" in ips
        assert "192.168.1.20" in ips

    def test_mark_quarantined(self):
        event = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.1.10")
        self.cache.update(event)
        self.cache.mark_quarantined("192.168.1.10", vlan_id=999)
        entry = self.cache.get("192.168.1.10")
        assert entry.vlan_id == 999

    def test_get_all_entries(self):
        e1 = ArpEvent(src_mac="aa:bb:cc:dd:ee:ff", src_ip="192.168.1.10")
        e2 = ArpEvent(src_mac="11:22:33:44:55:66", src_ip="192.168.1.20")
        self.cache.update(e1)
        self.cache.update(e2)
        entries = self.cache.get_all_entries()
        assert len(entries) == 2

    def test_get_change_history(self):
        self.cache.seed("192.168.1.1", "aa:bb:cc:dd:ee:ff")
        event = ArpEvent(src_mac="11:22:33:44:55:66", src_ip="192.168.1.1")
        self.cache.update(event)
        history = self.cache.get_change_history()
        assert len(history) == 1
        assert history[0]["old_mac"] == "aa:bb:cc:dd:ee:ff"
        assert history[0]["new_mac"] == "11:22:33:44:55:66"
