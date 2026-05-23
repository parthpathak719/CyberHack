"""
Threat Detection Engine for ARP Guardian.

Implements multiple detection heuristics for ARP cache poisoning
and maps each detection to MITRE ATT&CK T1557.002.

Detection methods:
  1. MAC-change detection     — IP's MAC binding changed
  2. MAC flapping             — Rapid MAC oscillation on same IP
  3. Gratuitous ARP flooding  — Excessive unsolicited announcements
  4. Gateway impersonation    — Someone claiming to be the gateway
  5. Duplicate IP detection   — Two MACs advertising the same IP
  6. ARP storm detection      — Rate-limit per source MAC exceeded

Limitations & known bypasses (documented for security depth):
  - Attacker can slow ARP rate below threshold (low-and-slow)
  - Initial binding is trusted on first-see (TOFU model)
  - Attacker can forge the legitimate MAC after quarantine release
  - VLAN hopping via double-tagging on misconfigured trunk ports
  - Detection blind if monitor's own ARP cache is poisoned first
"""

import time
import threading
from collections import defaultdict
from datetime import datetime
from typing import Callable, List, Optional

from .models import (
    Alert,
    ArpEvent,
    DetectionType,
    Severity,
    ATTACK_MAPPING,
)
from .arp_cache import ArpCache
from .logger import setup_logger

logger = setup_logger(__name__)


class ThreatDetector:
    """
    Processes ARP events against the binding cache and raises alerts
    when suspicious activity is detected.
    """

    def __init__(
        self,
        cache: ArpCache,
        gateway_ip: str = "192.168.100.1",
        gateway_mac: str = "02:42:c0:a8:64:01",
        mac_change_threshold: int = 2,
        gratuitous_threshold: int = 5,
        rate_threshold: int = 50,
        detection_window: int = 30,
        on_alert: Optional[Callable[[Alert], None]] = None,
    ):
        self._cache = cache
        self._gateway_ip = gateway_ip
        self._gateway_mac = gateway_mac.lower()
        self._mac_change_threshold = mac_change_threshold
        self._gratuitous_threshold = gratuitous_threshold
        self._rate_threshold = rate_threshold
        self._detection_window = detection_window
        self._on_alert = on_alert

        self._lock = threading.Lock()
        # src_mac -> list of timestamps (for rate limiting)
        self._arp_timestamps: dict[str, list[float]] = defaultdict(list)
        # ip -> list of timestamps for gratuitous ARPs
        self._gratuitous_timestamps: dict[str, list[float]] = defaultdict(list)
        # All alerts raised
        self._alerts: List[Alert] = []
        # Tracking first detection time for the 30-second window metric
        self._attack_start_time: Optional[float] = None
        self._first_detection_time: Optional[float] = None

    # ── Main Entry Point ───────────────────────────────────────────

    def analyze(self, event: ArpEvent) -> List[Alert]:
        """
        Analyze a single ARP event and return any alerts generated.

        This is called for every ARP packet captured by the monitor.
        """
        alerts: List[Alert] = []

        # Stage 1: Extract MAC and IP from event for processing
        # Stage 2: Validate current cache state and binding consistency
        # Stage 3: Track source MAC rate limits for volumetric analysis
        # Stage 4: Check specific heuristics for spoofing and impersonation

        # 1. Update binding cache and check for MAC change
        change = self._cache.update(event)
        if change:
            old_mac, new_mac = change
            alerts.extend(self._check_mac_change(event, old_mac, new_mac))

        # 2. Check for gateway impersonation
        gw_alert = self._check_gateway_impersonation(event)
        if gw_alert:
            alerts.append(gw_alert)

        # 3. Check for gratuitous ARP flood
        if event.is_gratuitous:
            grat_alert = self._check_gratuitous_flood(event)
            if grat_alert:
                alerts.append(grat_alert)

        # 4. Check ARP rate (storm detection)
        storm_alert = self._check_arp_rate(event)
        if storm_alert:
            alerts.append(storm_alert)

        # 5. Check for duplicate IPs (same IP from different MAC)
        dup_alert = self._check_duplicate_ip(event)
        if dup_alert:
            alerts.append(dup_alert)

        # Record and dispatch alerts
        for alert in alerts:
            self._record_alert(alert)

        return alerts

    # ── Detection Heuristics ───────────────────────────────────────

    def _check_mac_change(
        self, event: ArpEvent, old_mac: str, new_mac: str
    ) -> List[Alert]:
        """Detect MAC binding changes and MAC flapping."""
        alerts = []
        ip = event.src_ip
        change_count = self._cache.get_change_count(ip)
        is_trusted = self._cache.is_trusted(ip)

        # Check if this is a "recovery" — the gateway MAC returning to its
        # legitimate value after being spoofed.  We must NOT quarantine the
        # real gateway when this happens.
        is_gateway = (ip == self._gateway_ip)
        is_recovery = is_gateway and (new_mac == self._gateway_mac)

        # Determine severity and description based on target
        if is_gateway:
            if is_recovery:
                severity = Severity.MEDIUM.value
                desc = (
                    f"Gateway ({ip}) MAC restored to legitimate value "
                    f"{new_mac} (was spoofed as {old_mac}). Recovery detected."
                )
            else:
                severity = Severity.CRITICAL.value
                desc = (
                    f"CRITICAL: Gateway ({ip}) MAC changed from {old_mac} to "
                    f"{new_mac}. This is a strong indicator of ARP cache poisoning "
                    f"targeting the default gateway (MITRE ATT&CK {ATTACK_MAPPING.technique_id})."
                )
        elif is_trusted:
            severity = Severity.HIGH.value
            desc = (
                f"Trusted host {ip} MAC changed from {old_mac} to {new_mac}. "
                f"Possible ARP spoofing attack ({ATTACK_MAPPING.technique_id})."
            )
        else:
            severity = Severity.MEDIUM.value
            desc = (
                f"Host {ip} MAC changed from {old_mac} to {new_mac} "
                f"(change #{change_count}). Investigating."
            )

        # For recovery, the suspicious MAC is the OLD one (the spoofed value
        # that was in the cache), not the new legitimate MAC.
        alert_mac = old_mac if is_recovery else new_mac

        alerts.append(Alert(
            severity=severity,
            detection_type=DetectionType.MAC_CHANGE.value,
            description=desc,
            src_mac=alert_mac,
            src_ip=ip,
            target_ip=ip,
            previous_mac=old_mac if not is_recovery else new_mac,
            auto_response=(
                (is_gateway or change_count >= self._mac_change_threshold)
                and not is_recovery
            ),
        ))

        # Check for MAC flapping (rapid oscillation)
        if change_count >= self._mac_change_threshold:
            # Identify the attacker MAC as the one that is NOT the
            # legitimate gateway MAC.
            if is_gateway:
                attacker_mac = new_mac if new_mac != self._gateway_mac else old_mac
            else:
                attacker_mac = new_mac

            alerts.append(Alert(
                severity=Severity.CRITICAL.value,
                detection_type=DetectionType.MAC_FLAP.value,
                description=(
                    f"MAC flapping detected on {ip}: {change_count} MAC changes "
                    f"observed. Active ARP cache poisoning attack confirmed. "
                    f"Attacker MAC: {attacker_mac}."
                ),
                src_mac=attacker_mac,
                src_ip=ip,
                target_ip=ip,
                previous_mac=old_mac,
                auto_response=not is_recovery,
            ))

        # Track detection timing (for the 30-second KPI)
        if self._attack_start_time and not self._first_detection_time:
            self._first_detection_time = time.time()
            elapsed = self._first_detection_time - self._attack_start_time
            logger.info(
                f"⏱  Attack detected in {elapsed:.1f}s "
                f"(target: <{self._detection_window}s)"
            )

        return alerts

    def _check_gateway_impersonation(self, event: ArpEvent) -> Optional[Alert]:
        """Detect when a non-gateway MAC claims the gateway IP."""
        if event.src_ip != self._gateway_ip:
            return None

        src_mac = event.src_mac.lower()
        if src_mac == self._gateway_mac:
            return None  # Legitimate gateway traffic

        return Alert(
            severity=Severity.CRITICAL.value,
            detection_type=DetectionType.GATEWAY_IMPERSONATION.value,
            description=(
                f"GATEWAY IMPERSONATION: MAC {src_mac} is claiming to be the "
                f"gateway ({self._gateway_ip}), but the real gateway MAC is "
                f"{self._gateway_mac}. This is a definitive ARP spoofing "
                f"indicator ({ATTACK_MAPPING.technique_id})."
            ),
            src_mac=src_mac,
            src_ip=event.src_ip,
            target_ip=self._gateway_ip,
            previous_mac=self._gateway_mac,
            auto_response=True,
        )

    def _check_gratuitous_flood(self, event: ArpEvent) -> Optional[Alert]:
        """Detect excessive gratuitous ARP announcements."""
        ip = event.src_ip
        now = time.time()
        window = 60.0  # 1-minute window

        with self._lock:
            self._gratuitous_timestamps[ip].append(now)
            # Prune old entries
            self._gratuitous_timestamps[ip] = [
                t for t in self._gratuitous_timestamps[ip] if now - t < window
            ]
            count = len(self._gratuitous_timestamps[ip])

        if count >= self._gratuitous_threshold:
            return Alert(
                severity=Severity.HIGH.value,
                detection_type=DetectionType.GRATUITOUS_FLOOD.value,
                description=(
                    f"Gratuitous ARP flood from {event.src_mac} ({ip}): "
                    f"{count} unsolicited announcements in the last 60s "
                    f"(threshold: {self._gratuitous_threshold}). "
                    f"Likely ARP cache poisoning attempt."
                ),
                src_mac=event.src_mac,
                src_ip=ip,
                auto_response=False,  # Supporting indicator only; definitive heuristics handle quarantine
            )
        return None

    def _check_arp_rate(self, event: ArpEvent) -> Optional[Alert]:
        """Detect ARP storms from a single source MAC."""
        mac = event.src_mac.lower()
        now = time.time()
        window = 60.0

        with self._lock:
            self._arp_timestamps[mac].append(now)
            self._arp_timestamps[mac] = [
                t for t in self._arp_timestamps[mac] if now - t < window
            ]
            count = len(self._arp_timestamps[mac])

        if count >= self._rate_threshold:
            return Alert(
                severity=Severity.MEDIUM.value,
                detection_type=DetectionType.ARP_STORM.value,
                description=(
                    f"ARP storm from MAC {mac}: {count} ARP packets in 60s "
                    f"(threshold: {self._rate_threshold}). May indicate "
                    f"network reconnaissance or ARP-based attack."
                ),
                src_mac=mac,
                src_ip=event.src_ip,
            )
        return None

    def _check_duplicate_ip(self, event: ArpEvent) -> Optional[Alert]:
        """Detect when two different MACs claim the same IP."""
        ip = event.src_ip
        mac = event.src_mac.lower()

        # Find all MACs associated with this IP from the cache
        cached = self._cache.get(ip)
        if cached and cached.mac != mac and cached.change_count == 0:
            # First-time conflict — not yet recorded as a change
            return Alert(
                severity=Severity.HIGH.value,
                detection_type=DetectionType.DUPLICATE_IP.value,
                description=(
                    f"Duplicate IP conflict: {ip} is claimed by both "
                    f"{cached.mac} and {mac}. One of these is spoofed."
                ),
                src_mac=mac,
                src_ip=ip,
                previous_mac=cached.mac,
            )
        return None

    # ── Alert Management ───────────────────────────────────────────

    def _record_alert(self, alert: Alert) -> None:
        """Store and dispatch an alert."""
        with self._lock:
            self._alerts.append(alert)

        level = {
            Severity.CRITICAL.value: logger.critical,
            Severity.HIGH.value: logger.error,
            Severity.MEDIUM.value: logger.warning,
            Severity.LOW.value: logger.info,
            Severity.INFO.value: logger.info,
        }.get(alert.severity, logger.warning)

        level(
            f"🚨 [{alert.severity.upper()}] {alert.detection_type}: "
            f"{alert.description}"
        )

        if self._on_alert:
            self._on_alert(alert)

    def get_all_alerts(self) -> List[dict]:
        """Return all alerts as a list of dicts."""
        with self._lock:
            return [a.to_dict() for a in self._alerts]

    def get_detection_stats(self) -> dict:
        """Return summary statistics of detections."""
        with self._lock:
            by_type = defaultdict(int)
            by_severity = defaultdict(int)
            for a in self._alerts:
                by_type[a.detection_type] += 1
                by_severity[a.severity] += 1

            detection_time = None
            if self._attack_start_time and self._first_detection_time:
                detection_time = round(
                    self._first_detection_time - self._attack_start_time, 2
                )

            return {
                "total_alerts": len(self._alerts),
                "by_type": dict(by_type),
                "by_severity": dict(by_severity),
                "detection_time_sec": detection_time,
                "detection_target_sec": self._detection_window,
                "mitre_technique": ATTACK_MAPPING.technique_id,
            }

    def set_attack_start_time(self, t: Optional[float] = None) -> None:
        """Record when an attack began (for timing measurement)."""
        self._attack_start_time = t or time.time()
        self._first_detection_time = None
