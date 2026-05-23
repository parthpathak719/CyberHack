"""
Simulated Managed Switch — Flask REST API.

Emulates a Cisco-style managed switch with:
  - MAC address table
  - VLAN port assignments
  - Port enable/disable
  - Quarantine VLAN (999)

This replaces a real switch for the Docker demo environment.
In production, use the SNMP back-end instead.

Endpoints:
  GET  /api/health          — health check
  GET  /api/mac-table       — full MAC table or lookup by ?mac=
  GET  /api/port/<name>     — port status
  POST /api/port/vlan       — set port VLAN  { port, vlan_id }
  GET  /api/vlans           — VLAN list
  GET  /api/log             — action log
"""

from flask import Flask, request, jsonify
from datetime import datetime
import threading
import json

app = Flask(__name__)


# ── Switch State ───────────────────────────────────────────────────

class SwitchState:
    """In-memory state of the simulated managed switch."""

    def __init__(self):
        self._lock = threading.Lock()

        # Port configuration: port_name -> { vlan, status, mac, description }
        self.ports = {
            "Gi0/1": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:01", "description": "Gateway", "speed": "1Gbps"},
            "Gi0/2": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:0a", "description": "Workstation", "speed": "1Gbps"},
            "Gi0/3": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:14", "description": "Server", "speed": "1Gbps"},
            "Gi0/4": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:1e", "description": "Attacker", "speed": "1Gbps"},
            "Gi0/5": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:28", "description": "ARP Monitor", "speed": "1Gbps"},
            "Gi0/6": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:1f", "description": "Attacker 2", "speed": "1Gbps"},
            "Gi0/7": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:20", "description": "Attacker 3", "speed": "1Gbps"},
            "Gi0/8": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:0b", "description": "Workstation 2", "speed": "1Gbps"},
            "Gi0/9": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:0c", "description": "Workstation 3", "speed": "1Gbps"},
            "Gi0/10": {"vlan": 1, "status": "up", "mac": "02:42:c0:a8:64:15", "description": "Server 2", "speed": "1Gbps"},
        }

        # VLAN database
        self.vlans = {
            1: {"name": "DEFAULT", "description": "Default VLAN"},
            10: {"name": "SERVERS", "description": "Server VLAN"},
            20: {"name": "WORKSTATIONS", "description": "Workstation VLAN"},
            999: {"name": "QUARANTINE", "description": "Isolation VLAN for threats"},
        }

        # MAC address table: mac -> port_name
        self.mac_table = {
            port["mac"]: name for name, port in self.ports.items()
        }

        # Action log
        self.action_log = []

    def set_port_vlan(self, port_name: str, vlan_id: int) -> dict:
        """Move a port to a different VLAN."""
        with self._lock:
            if port_name not in self.ports:
                return {"success": False, "error": f"Port {port_name} not found"}
            if vlan_id not in self.vlans:
                return {"success": False, "error": f"VLAN {vlan_id} not found"}

            old_vlan = self.ports[port_name]["vlan"]
            self.ports[port_name]["vlan"] = vlan_id

            action = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "action": "vlan_change",
                "port": port_name,
                "from_vlan": old_vlan,
                "to_vlan": vlan_id,
                "mac": self.ports[port_name]["mac"],
                "description": self.ports[port_name]["description"],
            }
            self.action_log.append(action)

            vlan_name = self.vlans[vlan_id]["name"]
            return {
                "success": True,
                "status": f"Port {port_name} moved to VLAN {vlan_id} ({vlan_name})",
                "action": action,
            }

    def get_port_for_mac(self, mac: str) -> dict:
        """Look up which port a MAC is on."""
        with self._lock:
            mac = mac.lower()
            port = self.mac_table.get(mac)
            if port:
                return {"port": port, "mac": mac, "found": True}
            
            # --- DYNAMIC MAC FALLBACK FOR DOCKER DEMO ---
            # If the MAC is unknown, automatically map it to the Attacker port (Gi0/4)
            # so the quarantine demo works without hardcoding Docker's random MACs.
            self.mac_table[mac] = "Gi0/4"
            self.ports["Gi0/4"]["mac"] = mac
            return {"port": "Gi0/4", "mac": mac, "found": True}


# Singleton state
switch = SwitchState()


# ── Routes ─────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "switch": "ARP-Guardian-SW01", "uptime": "simulated"})


@app.route("/api/mac-table")
def mac_table():
    mac_filter = request.args.get("mac", "").lower()
    if mac_filter:
        result = switch.get_port_for_mac(mac_filter)
        return jsonify(result)

    entries = []
    for mac, port_name in switch.mac_table.items():
        port_info = switch.ports.get(port_name, {})
        entries.append({
            "mac": mac,
            "port": port_name,
            "vlan": port_info.get("vlan", 0),
            "description": port_info.get("description", ""),
        })
    return jsonify({"entries": entries})


@app.route("/api/port/<port_name>")
def port_status(port_name):
    port_name = port_name.replace("-", "/")  # URL-safe
    if port_name in switch.ports:
        info = switch.ports[port_name].copy()
        info["port"] = port_name
        return jsonify(info)
    return jsonify({"error": "Port not found"}), 404


@app.route("/api/port/vlan", methods=["POST"])
def set_vlan():
    data = request.get_json()
    if not data or "port" not in data or "vlan_id" not in data:
        return jsonify({"error": "Missing port or vlan_id"}), 400

    result = switch.set_port_vlan(data["port"], data["vlan_id"])
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/vlans")
def vlans():
    vlan_list = [
        {"id": vid, "name": info["name"], "description": info["description"]}
        for vid, info in switch.vlans.items()
    ]
    return jsonify({"vlans": vlan_list})


@app.route("/api/ports")
def all_ports():
    port_list = []
    for name, info in switch.ports.items():
        entry = info.copy()
        entry["port"] = name
        port_list.append(entry)
    return jsonify({"ports": port_list})


@app.route("/api/log")
def action_log():
    return jsonify({"log": switch.action_log})


# ── Entry Point ────────────────────────────────────────────────────

if __name__ == "__main__":
    print("🔌 Switch Simulator starting on port 5000...")
    app.run(host="0.0.0.0", port=5000, debug=False)
