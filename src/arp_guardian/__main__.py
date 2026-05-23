"""
ARP Guardian — Main Entry Point & REST API Server.

Usage:
  # Simulation mode (no root, no Docker — ideal for demo)
  python -m src.arp_guardian --simulate

  # Live capture mode (requires root/sudo)
  sudo python -m src.arp_guardian --iface eth0

  # With SNMP back-end instead of simulated switch
  sudo python -m src.arp_guardian --iface eth0 --snmp

The embedded REST API serves data to the browser dashboard at
http://localhost:8081/api/*
"""

import argparse
import json
import os
import signal
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from .config import Config
from .models import ATTACK_MAPPING
from .arp_cache import ArpCache
from .detector import ThreatDetector
from .vlan_manager import VlanManager
from .alert_engine import AlertEngine
from .arp_monitor import ArpMonitor
from .simulator import Simulator
from .logger import setup_logger


# ── Globals (module-level for HTTP handler access) ─────────────────
_cache: ArpCache = None
_detector: ThreatDetector = None
_vlan_mgr: VlanManager = None
_alert_engine: AlertEngine = None
_monitor = None          # ArpMonitor or Simulator
_config: Config = None
_events_log: list = []   # All raw ARP events for the dashboard
_events_lock = threading.Lock()
_pcap_writer = None

try:
    from scapy.all import Ether, ARP
    from scapy.utils import PcapWriter
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = setup_logger("arp_guardian")


# ── REST API Handler ───────────────────────────────────────────────

class ApiHandler(BaseHTTPRequestHandler):
    """
    Lightweight REST API for the dashboard.

    Endpoints:
      GET /api/health        — health check
      GET /api/status        — overall system status
      GET /api/events        — raw ARP event log
      GET /api/alerts        — detection alerts
      GET /api/cache         — ARP binding table
      GET /api/quarantine    — quarantine actions
      GET /api/stats         — detection statistics
      GET /api/mitre         — MITRE ATT&CK mapping
      GET /api/topology      — network host topology
    """

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        routes = {
            "/api/health": self._health,
            "/api/status": self._status,
            "/api/events": self._events,
            "/api/alerts": self._alerts,
            "/api/cache": self._arp_cache,
            "/api/quarantine": self._quarantine,
            "/api/stats": self._stats,
            "/api/mitre": self._mitre,
            "/api/topology": self._topology,
        }

        handler = routes.get(path)
        if handler:
            handler(params)
        else:
            self._json_response({"error": "not found"}, 404)

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def _json_response(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, fmt, *args):
        """Suppress default HTTP log noise."""
        pass

    # ── Route Handlers ─────────────────────────────────────────────

    def _health(self, params):
        self._json_response({"status": "ok", "version": "1.0.0"})

    def _status(self, params):
        monitor_stats = {}
        if hasattr(_monitor, "get_stats"):
            monitor_stats = _monitor.get_stats()

        self._json_response({
            "mode": "simulation" if _config.simulation_mode else "live",
            "monitor": monitor_stats,
            "cache_size": _cache.size() if _cache else 0,
            "alert_summary": _alert_engine.get_summary() if _alert_engine else {},
            "detection_stats": _detector.get_detection_stats() if _detector else {},
        })

    def _events(self, params):
        limit = int(params.get("limit", [100])[0])
        with _events_lock:
            recent = _events_log[-limit:]
        self._json_response({"events": recent, "total": len(_events_log)})

    def _alerts(self, params):
        alerts = _detector.get_all_alerts() if _detector else []
        self._json_response({"alerts": alerts, "total": len(alerts)})

    def _arp_cache(self, params):
        entries = _cache.get_all_entries() if _cache else []
        history = _cache.get_change_history() if _cache else []
        self._json_response({
            "entries": entries,
            "changes": history,
            "size": len(entries),
        })

    def _quarantine(self, params):
        actions = _vlan_mgr.get_all_actions() if _vlan_mgr else []
        quarantined = _vlan_mgr.get_quarantined_macs() if _vlan_mgr else []
        self._json_response({
            "actions": actions,
            "quarantined_macs": quarantined,
        })

    def _stats(self, params):
        stats = _detector.get_detection_stats() if _detector else {}
        self._json_response(stats)

    def _mitre(self, params):
        self._json_response(ATTACK_MAPPING.to_dict())

    def _topology(self, params):
        from .simulator import HOSTS
        hosts = []
        quarantined = _vlan_mgr.get_quarantined_macs() if _vlan_mgr else []
        for name, info in HOSTS.items():
            hosts.append({
                "name": name,
                "ip": info["ip"],
                "mac": info["mac"],
                "port": info.get("port", ""),
                "is_quarantined": info["mac"] in quarantined,
                "vlan": 999 if info["mac"] in quarantined else 1,
                "role": "attacker" if "attacker" in name else name,
            })
        self._json_response({"hosts": hosts})


# ── Event Processing ───────────────────────────────────────────────

def on_arp_event(event):
    """Callback invoked for every ARP event (live or simulated)."""
    global _events_log

    # Simulate physical VLAN isolation: if the host is quarantined, its traffic 
    # would not reach our network segment in the real world.
    quarantined_macs = _vlan_mgr.get_quarantined_macs() if _vlan_mgr else []
    if event.src_mac in quarantined_macs:
        return

    if _pcap_writer and SCAPY_AVAILABLE:
        try:
            eth = Ether(src=event.src_mac, dst=event.dst_mac)
            arp = ARP(
                op=event.operation,
                hwsrc=event.src_mac,
                psrc=event.src_ip,
                hwdst=event.dst_mac,
                pdst=event.dst_ip
            )
            _pcap_writer.write(eth/arp)
        except Exception as e:
            logger.error(f"Failed to write to PCAP: {e}")

    # Store raw event
    event_dict = {
        "id": event.id,
        "timestamp": event.timestamp,
        "src_mac": event.src_mac,
        "dst_mac": event.dst_mac,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "operation": event.operation,
        "is_gratuitous": event.is_gratuitous,
        "raw": event.raw_summary,
    }
    with _events_lock:
        _events_log.append(event_dict)

    # Run through threat detector
    alerts = _detector.analyze(event)

    # Process each alert through the alert engine
    for alert in alerts:
        _alert_engine.process_alert(alert)


# ── Main ───────────────────────────────────────────────────────────

def main():
    global _cache, _detector, _vlan_mgr, _alert_engine, _monitor, _config

    parser = argparse.ArgumentParser(
        description="ARP Guardian — ARP Spoofing Detection & Network Segmentation"
    )
    parser.add_argument(
        "--simulate", action="store_true",
        help="Run in simulation mode (no real network capture)",
    )
    parser.add_argument(
        "--iface", default="eth0",
        help="Network interface to monitor (default: eth0)",
    )
    parser.add_argument(
        "--snmp", action="store_true",
        help="Use SNMP for switch communication instead of REST API",
    )
    parser.add_argument(
        "--no-quarantine", action="store_true",
        help="Disable automatic quarantine (detection only)",
    )
    parser.add_argument(
        "--api-port", type=int, default=8081,
        help="REST API port for dashboard (default: 8081)",
    )
    parser.add_argument(
        "--switch-url", default="http://localhost:5000",
        help="Simulated switch API URL",
    )
    parser.add_argument(
        "--attack-delay", type=float, default=10.0,
        help="Seconds before simulated attack starts (default: 10)",
    )
    args = parser.parse_args()

    # ── Configuration ──────────────────────────────────────────────
    _config = Config.from_env()
    _config.simulation_mode = args.simulate
    _config.interface = args.iface
    _config.use_snmp = args.snmp
    _config.auto_quarantine = not args.no_quarantine
    _config.api_port = args.api_port
    _config.switch_api_url = args.switch_url

    # ── Create data directory ──────────────────────────────────────
    os.makedirs("data", exist_ok=True)

    global _pcap_writer
    if SCAPY_AVAILABLE:
        pcap_file = os.path.join("data", "simulation.pcap")
        _pcap_writer = PcapWriter(pcap_file, append=False, sync=True)
        logger.info(f"PCAP capture enabled. Writing traffic to {pcap_file}")

    # ── Banner ─────────────────────────────────────────────────────
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║           🛡️  ARP GUARDIAN v1.0.0                       ║")
    print("║   ARP Spoofing Detection & Network Segmentation        ║")
    print("║   MITRE ATT&CK: T1557.002 — ARP Cache Poisoning       ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    mode = "SIMULATION" if _config.simulation_mode else f"LIVE ({_config.interface})"
    print(f"  Mode:            {mode}")
    print(f"  Auto-Quarantine: {'ON' if _config.auto_quarantine else 'OFF'}")
    print(f"  Switch Backend:  {'SNMP' if _config.use_snmp else 'REST API'}")
    print(f"  API Server:      http://localhost:{_config.api_port}")
    print(f"  Dashboard:       http://localhost:8080")
    print()

    # ── Initialise Components ──────────────────────────────────────

    # 1. ARP cache — seed with gateway
    _cache = ArpCache(cache_ttl_sec=_config.cache_ttl_sec)
    _cache.seed(_config.gateway_ip, _config.gateway_mac, is_trusted=True)

    # 2. VLAN manager
    _vlan_mgr = VlanManager(
        use_snmp=_config.use_snmp,
        switch_api_url=_config.switch_api_url,
        snmp_host=_config.switch_snmp_host,
        snmp_community=_config.switch_snmp_community,
        quarantine_vlan=_config.quarantine_vlan_id,
        normal_vlan=_config.normal_vlan_id,
    )

    # 3. Alert engine
    _alert_engine = AlertEngine(
        vlan_manager=_vlan_mgr,
        auto_quarantine=_config.auto_quarantine,
    )

    # 4. Threat detector
    _detector = ThreatDetector(
        cache=_cache,
        gateway_ip=_config.gateway_ip,
        gateway_mac=_config.gateway_mac,
        mac_change_threshold=_config.mac_change_threshold,
        gratuitous_threshold=_config.gratuitous_arp_threshold,
        rate_threshold=_config.arp_rate_threshold,
        detection_window=_config.detection_window_sec,
        on_alert=None,  # Alerts go through alert_engine instead
    )

    # 5. Start API server
    api_server = HTTPServer(("0.0.0.0", _config.api_port), ApiHandler)
    api_thread = threading.Thread(
        target=api_server.serve_forever,
        name="api-server",
        daemon=True,
    )
    api_thread.start()
    logger.info(f"REST API server started on port {_config.api_port}")

    # 6. Start monitor or simulator
    if _config.simulation_mode:
        _monitor = Simulator(
            on_event=on_arp_event,
            attack_delay_sec=args.attack_delay,
            on_attack_start=lambda: _detector.set_attack_start_time(),
        )
        _monitor.start()
    else:
        _monitor = ArpMonitor(
            interface=_config.interface,
            on_event=on_arp_event,
        )
        _monitor.start()

    # ── Graceful Shutdown ──────────────────────────────────────────
    def shutdown(sig, frame):
        print("\n\n🛑 Shutting down ARP Guardian...")
        _monitor.stop()
        api_server.shutdown()

        # Write final summary
        stats = _detector.get_detection_stats()
        print("\n── Detection Summary ────────────────────────────")
        print(f"  Total alerts:       {stats['total_alerts']}")
        print(f"  Detection time:     {stats.get('detection_time_sec', 'N/A')}s")
        print(f"  Target:             <{stats['detection_target_sec']}s")
        print(f"  MITRE Technique:    {stats['mitre_technique']}")
        print(f"  Quarantined hosts:  {len(_vlan_mgr.get_quarantined_macs())}")
        print("─────────────────────────────────────────────────\n")

        # Save final state
        summary = {
            "detection_stats": stats,
            "alerts": _detector.get_all_alerts(),
            "quarantine_actions": _vlan_mgr.get_all_actions(),
            "arp_cache": _cache.get_all_entries(),
            "mitre": ATTACK_MAPPING.to_dict(),
        }
        with open("data/final_summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        logger.info("Final summary saved to data/final_summary.json")

        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Keep main thread alive
    logger.info("ARP Guardian is running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
