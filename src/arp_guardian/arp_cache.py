"""
ARP Binding Table Manager.

Maintains a trusted IP-to-MAC binding table and tracks all changes.
When a binding changes, the event is recorded and the change count
is incremented — the threat detector uses this to flag attacks.

Defence approach:
  - Seed the cache with known-good bindings (e.g., gateway).
  - Each new binding is tentatively trusted until contradicted.
  - MAC changes increment a counter; rapid changes trigger alerts.
"""

import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .models import ArpEntry, ArpEvent
from .logger import setup_logger

logger = setup_logger(__name__)


class ArpCache:
    """
    Thread-safe ARP binding table.

    Stores the most recently observed MAC for each IP and records
    the history of every binding change.
    """

    def __init__(self, cache_ttl_sec: int = 300):
        self._lock = threading.Lock()
        # ip -> ArpEntry
        self._table: Dict[str, ArpEntry] = {}
        # List of (timestamp, ip, old_mac, new_mac) tuples
        self._change_history: List[Tuple[str, str, str, str]] = []
        self._cache_ttl = cache_ttl_sec

    # ── Public API ─────────────────────────────────────────────────

    def seed(self, ip: str, mac: str, is_trusted: bool = True) -> None:
        """
        Pre-populate a known-good binding (e.g., default gateway).
        Trusted entries raise higher-severity alerts if overwritten.
        """
        with self._lock:
            self._table[ip] = ArpEntry(
                ip=ip,
                mac=mac.lower(),
                is_trusted=is_trusted,
                vlan_id=1,
            )
            logger.info(f"Seeded ARP cache: {ip} -> {mac} (trusted={is_trusted})")

    def update(self, event: ArpEvent) -> Optional[Tuple[str, str]]:
        """
        Process an ARP event and update the binding table.

        Returns:
            (old_mac, new_mac) if the MAC changed, else None.
        """
        ip = event.src_ip
        mac = event.src_mac.lower()
        now = datetime.utcnow().isoformat() + "Z"

        with self._lock:
            if ip in self._table:
                existing = self._table[ip]

                if existing.mac != mac:
                    old_mac = existing.mac
                    # Record the change
                    existing.mac = mac
                    existing.last_seen = now
                    existing.change_count += 1
                    self._change_history.append((now, ip, old_mac, mac))

                    logger.warning(
                        f"MAC CHANGE detected: {ip} was {old_mac} now {mac} "
                        f"(change #{existing.change_count})"
                    )
                    return (old_mac, mac)
                else:
                    # Same MAC — just refresh timestamp
                    existing.last_seen = now
                    return None
            else:
                # First time seeing this IP
                self._table[ip] = ArpEntry(
                    ip=ip,
                    mac=mac,
                    first_seen=now,
                    last_seen=now,
                )
                logger.info(f"New ARP binding: {ip} -> {mac}")
                return None

    def get(self, ip: str) -> Optional[ArpEntry]:
        """Look up a binding by IP."""
        with self._lock:
            return self._table.get(ip)

    def get_mac_for_ip(self, ip: str) -> Optional[str]:
        """Return the currently bound MAC for an IP, or None."""
        entry = self.get(ip)
        return entry.mac if entry else None

    def is_trusted(self, ip: str) -> bool:
        """Check if an IP has a trusted (seeded) binding."""
        entry = self.get(ip)
        return entry.is_trusted if entry else False

    def get_change_count(self, ip: str) -> int:
        """Return how many times this IP's MAC has changed."""
        entry = self.get(ip)
        return entry.change_count if entry else 0

    def get_all_entries(self) -> List[dict]:
        """Return a snapshot of all cache entries as dicts."""
        with self._lock:
            return [
                {
                    "ip": e.ip,
                    "mac": e.mac,
                    "first_seen": e.first_seen,
                    "last_seen": e.last_seen,
                    "is_trusted": e.is_trusted,
                    "change_count": e.change_count,
                    "vlan_id": e.vlan_id,
                }
                for e in self._table.values()
            ]

    def get_change_history(self) -> List[dict]:
        """Return a list of all MAC-change events."""
        with self._lock:
            return [
                {
                    "timestamp": ts,
                    "ip": ip,
                    "old_mac": old,
                    "new_mac": new,
                }
                for ts, ip, old, new in self._change_history
            ]

    def find_ips_by_mac(self, mac: str) -> List[str]:
        """Find all IPs currently associated with a given MAC."""
        mac = mac.lower()
        with self._lock:
            return [ip for ip, e in self._table.items() if e.mac == mac]

    def mark_quarantined(self, ip: str, vlan_id: int = 999) -> None:
        """Mark an entry as quarantined (moved to isolation VLAN)."""
        with self._lock:
            if ip in self._table:
                self._table[ip].vlan_id = vlan_id
                logger.info(f"Marked {ip} as quarantined (VLAN {vlan_id})")

    def size(self) -> int:
        """Return the number of entries in the cache."""
        with self._lock:
            return len(self._table)
