"""
ARP Monitor Daemon — Core Packet Sniffer.

Uses scapy to continuously sniff ARP packets on the network interface.
Each captured packet is parsed into an ArpEvent and passed to the
ThreatDetector for analysis.

In simulation mode, synthetic ARP events are generated instead of
sniffing the real network.
"""

import threading
import time
from typing import Callable, Optional

from .models import ArpEvent, ArpOperation
from .logger import setup_logger

logger = setup_logger(__name__)

# ── Scapy import with graceful fallback ────────────────────────────
# scapy requires root on Linux; provide a clear error if unavailable.
try:
    from scapy.all import ARP, Ether, sniff, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning(
        "scapy not installed or not available. "
        "Live capture disabled — use simulation mode."
    )


class ArpMonitor:
    """
    Continuous ARP packet capture daemon.

    Sniffs ARP traffic on the specified interface and invokes a callback
    for each parsed event.  Runs in a background thread so the main
    application can do other work concurrently.
    """

    def __init__(
        self,
        interface: str = "eth0",
        on_event: Optional[Callable[[ArpEvent], None]] = None,
    ):
        self._interface = interface
        self._on_event = on_event
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._start_time: Optional[float] = None

    # ── Lifecycle ──────────────────────────────────────────────────

    def start(self) -> None:
        """Start the ARP sniffing thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "scapy is required for live capture. "
                "Install it with: pip install scapy"
            )

        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(
            target=self._sniff_loop,
            name="arp-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"ARP Monitor started on interface '{self._interface}'"
        )

    def stop(self) -> None:
        """Signal the sniffer to stop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        logger.info(
            f"ARP Monitor stopped. Captured {self._packet_count} packets."
        )

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packet_count(self) -> int:
        return self._packet_count

    # ── Internal ───────────────────────────────────────────────────

    def _sniff_loop(self) -> None:
        """Main sniffing loop — runs in a background thread."""
        logger.info("Sniffing for ARP packets (filter='arp')...")

        try:
            sniff(
                iface=self._interface,
                filter="arp",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.critical(
                "Permission denied — ARP sniffing requires root/sudo. "
                "Run with: sudo python -m src.arp_guardian"
            )
            self._running = False
        except OSError as e:
            logger.critical(f"Network error: {e}")
            self._running = False

    def _process_packet(self, pkt) -> None:
        """
        Parse a raw scapy packet into an ArpEvent.

        Scapy ARP fields:
          pkt[ARP].op    — 1 = who-has (request), 2 = is-at (reply)
          pkt[ARP].hwsrc — sender MAC
          pkt[ARP].psrc  — sender IP
          pkt[ARP].hwdst — target MAC
          pkt[ARP].pdst  — target IP
        """
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        self._packet_count += 1

        # Determine if this is a gratuitous ARP:
        # A gratuitous ARP is a reply (or request) where sender IP == target IP
        is_gratuitous = arp.psrc == arp.pdst

        # Build event
        event = ArpEvent(
            src_mac=arp.hwsrc,
            dst_mac=arp.hwdst,
            src_ip=arp.psrc,
            dst_ip=arp.pdst,
            operation=arp.op,
            is_gratuitous=is_gratuitous,
            raw_summary=pkt.summary(),
        )

        # Dispatch to callback
        if self._on_event:
            self._on_event(event)

    def get_stats(self) -> dict:
        """Return monitor statistics."""
        uptime = time.time() - self._start_time if self._start_time else 0
        return {
            "interface": self._interface,
            "running": self._running,
            "packets_captured": self._packet_count,
            "uptime_sec": round(uptime, 1),
            "packets_per_sec": round(
                self._packet_count / uptime, 2
            ) if uptime > 0 else 0,
        }
