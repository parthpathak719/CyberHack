"""
Simulation Mode for ARP Guardian.

Generates synthetic ARP events to demonstrate the full detection and
quarantine pipeline without requiring real network access or Docker.

Scenario:
  1. Normal traffic phase — gateway, workstation, and server exchange
     legitimate ARP requests and replies.
  2. Attack phase — an attacker sends spoofed ARP replies claiming to
     be the gateway, poisoning the victim's ARP cache.
  3. Detection & response — the detector fires alerts and the VLAN
     manager quarantines the attacker.
  4. Post-quarantine — the attacker's traffic stops.

This mode is ideal for:
  - macOS demos without root/sudo
  - Hackathon presentations
  - Unit and integration testing
"""

import time
import random
import threading
from datetime import datetime
from typing import Callable, Optional, List

from .models import ArpEvent
from .logger import setup_logger

logger = setup_logger(__name__)


# ── Simulated Network Topology ─────────────────────────────────────

HOSTS = {
    "gateway":     {"ip": "192.168.100.1",  "mac": "02:42:c0:a8:64:01", "port": "Gi0/1"},
    "workstation": {"ip": "192.168.100.10", "mac": "02:42:c0:a8:64:0a", "port": "Gi0/2"},
    "workstation2":{"ip": "192.168.100.11", "mac": "02:42:c0:a8:64:0b", "port": "Gi0/8"},
    "workstation3":{"ip": "192.168.100.12", "mac": "02:42:c0:a8:64:0c", "port": "Gi0/9"},
    "server":      {"ip": "192.168.100.20", "mac": "02:42:c0:a8:64:14", "port": "Gi0/3"},
    "server2":     {"ip": "192.168.100.21", "mac": "02:42:c0:a8:64:15", "port": "Gi0/10"},
    "attacker":    {"ip": "192.168.100.30", "mac": "02:42:c0:a8:64:1e", "port": "Gi0/4"},
    "attacker2":   {"ip": "192.168.100.31", "mac": "02:42:c0:a8:64:1f", "port": "Gi0/6"},
    "attacker3":   {"ip": "192.168.100.32", "mac": "02:42:c0:a8:64:20", "port": "Gi0/7"},
    "monitor":     {"ip": "192.168.100.254", "mac": "02:42:c0:a8:64:28", "port": "Gi0/5"},
}


class Simulator:
    """
    Generates synthetic ARP events for demonstration.

    Phases:
      Phase 1 (0–10s):   Normal ARP traffic between hosts.
      Phase 2 (10–40s):  Attacker sends spoofed ARP replies.
      Phase 3 (40s+):    Post-quarantine, attacker silenced.
    """

    def __init__(
        self,
        on_event: Optional[Callable[[ArpEvent], None]] = None,
        attack_delay_sec: float = 10.0,
        attack_duration_sec: float = 30.0,
        normal_interval_sec: float = 2.0,
        attack_interval_sec: float = 0.5,
        on_attack_start: Optional[Callable[[], None]] = None,
        on_release: Optional[Callable[[], None]] = None,
    ):
        self._on_event = on_event
        self._attack_delay = attack_delay_sec
        self._attack_duration = attack_duration_sec
        self._normal_interval = normal_interval_sec
        self._attack_interval = attack_interval_sec
        self._on_attack_start = on_attack_start
        self._on_release = on_release
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._phase = "init"
        self._events_generated = 0

    def start(self) -> None:
        """Start the simulation in a background thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._run_scenario,
            name="simulator",
            daemon=True,
        )
        self._thread.start()
        logger.info("🎬 Simulation started")

    def stop(self) -> None:
        """Stop the simulation."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info(
            f"Simulation stopped. Generated {self._events_generated} events."
        )

    @property
    def phase(self) -> str:
        return self._phase

    @property
    def events_generated(self) -> int:
        return self._events_generated

    # ── Scenario Runner ────────────────────────────────────────────

    def _run_scenario(self) -> None:
        """Execute the three-phase simulation scenario."""
        start_time = time.time()

        # ── Phase 1: Normal Traffic ────────────────────────────────
        self._phase = "normal"
        logger.info("📡 Phase 1: Normal ARP traffic")

        while self._running and (time.time() - start_time) < self._attack_delay:
            self._emit_normal_traffic()
            time.sleep(self._normal_interval)

        if not self._running:
            return

        cycle_count = 1
        while self._running:
            logger.info(f"🔄 Starting Cycle {cycle_count}")
            
            # ── Attack Phase ────────────────────────────────────────
            self._phase = "attack"
            logger.info("⚔️  Attack Phase: ARP spoofing attack begins!")
            if self._on_attack_start and cycle_count == 1:
                self._on_attack_start()
            
            # Brief pause before attack to simulate realistic timing on first cycle
            if cycle_count == 1:
                time.sleep(random.uniform(0.1, 0.5))

            attack_start = time.time()
            while self._running and (time.time() - attack_start) < 15.0:
                self._emit_attack_traffic()
                if random.random() < 0.3:
                    self._emit_normal_traffic()
                time.sleep(self._attack_interval)
                
            if not self._running:
                break

            # ── Quarantine Period ───────────────────────────────────
            self._phase = "post_quarantine"
            logger.info("🛡️  Quarantine Period: Attacker silenced (15s)")
            
            post_q_start = time.time()
            while self._running and (time.time() - post_q_start) < 15.0:
                self._emit_normal_traffic()
                time.sleep(self._normal_interval)
                
            if not self._running:
                break

            # ── Release Phase ───────────────────────────────────────
            self._phase = "release"
            logger.info("🔓 Release Phase: Releasing attacker back to normal VLAN")
            if self._on_release:
                self._on_release()
                
            rel_start = time.time()
            while self._running and (time.time() - rel_start) < 10.0:
                self._emit_normal_traffic()
                time.sleep(self._normal_interval)
                
            cycle_count += 1

    # ── Traffic Generators ─────────────────────────────────────────

    def _emit_normal_traffic(self) -> None:
        """Generate normal ARP request/reply pairs between random legitimate hosts."""
        # Get all non-attacker hosts
        legit_hosts = [v for k, v in HOSTS.items() if "attacker" not in k]
        
        # Pick two distinct hosts
        src, dst = random.sample(legit_hosts, 2)
        
        # Either Request or Reply
        op = random.choice([1, 2])
        event = self._make_event(src=src, dst=dst, operation=op)
        self._dispatch(event)

    def _emit_attack_traffic(self) -> None:
        """
        The attacker claims to be the gateway (192.168.100.1) but
        uses its own MAC address, poisoning the victim's cache.
        """
        attackers = [v for k, v in HOSTS.items() if "attacker" in k]
        active_attacker = random.choice(attackers)

        # Spoofed reply: "I am the gateway (192.168.100.1)" from attacker MAC
        spoofed_reply = ArpEvent(
            src_mac=active_attacker["mac"],        # Attacker's real MAC
            dst_mac=HOSTS["workstation"]["mac"],   # Targeted at workstation
            src_ip=HOSTS["gateway"]["ip"],         # Claiming to be gateway
            dst_ip=HOSTS["workstation"]["ip"],
            operation=2,                           # is-at (reply)
            is_gratuitous=False,
            raw_summary=(
                f"ARP is-at {HOSTS['gateway']['ip']} says "
                f"{active_attacker['mac']} (SPOOFED)"
            ),
        )
        self._dispatch(spoofed_reply)

        # Sometimes also send gratuitous ARP claiming to be gateway
        if random.random() < 0.4:
            gratuitous_spoof = ArpEvent(
                src_mac=active_attacker["mac"],
                dst_mac="ff:ff:ff:ff:ff:ff",
                src_ip=HOSTS["gateway"]["ip"],
                dst_ip=HOSTS["gateway"]["ip"],
                operation=2,
                is_gratuitous=True,
                raw_summary=(
                    f"ARP gratuitous {HOSTS['gateway']['ip']} -> "
                    f"{active_attacker['mac']} (SPOOFED)"
                ),
            )
            self._dispatch(gratuitous_spoof)

    def _make_event(
        self, src: dict, dst: dict,
        operation: int = 2, is_gratuitous: bool = False,
    ) -> ArpEvent:
        """Helper to build an ARP event from host dicts."""
        return ArpEvent(
            src_mac=src["mac"],
            dst_mac=dst["mac"],
            src_ip=src["ip"],
            dst_ip=dst["ip"],
            operation=operation,
            is_gratuitous=is_gratuitous,
            raw_summary=f"ARP op={operation} {src['ip']} -> {dst['ip']}",
        )

    def _dispatch(self, event: ArpEvent) -> None:
        """Send event to callback."""
        self._events_generated += 1
        if self._on_event:
            self._on_event(event)

    def get_stats(self) -> dict:
        """Return simulation statistics."""
        return {
            "phase": self._phase,
            "events_generated": self._events_generated,
            "running": self._running,
            "hosts": {name: info for name, info in HOSTS.items()},
        }
