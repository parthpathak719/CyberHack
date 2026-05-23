/**
 * ARP Guardian — Dashboard Frontend Application
 *
 * Polls the REST API every 2 seconds and renders:
 *   - Network topology visualization (canvas)
 *   - Real-time attack timeline
 *   - ARP binding table with change highlighting
 *   - Detection alert feed
 *   - Quarantine actions
 *   - MITRE ATT&CK mapping
 *   - Statistics cards with counters
 */

// ── Configuration ─────────────────────────────────────────────────
const API_BASE = "";  // Proxied through dashboard server
const POLL_INTERVAL = 2000;  // 2 seconds

// ── State ─────────────────────────────────────────────────────────
let state = {
    connected: false,
    events: [],
    alerts: [],
    cache: [],
    quarantine: [],
    stats: {},
    topology: [],
    mitre: {},
    prevAlertCount: 0,
    prevEventCount: 0,
    animFrame: null,
};

// ── Initialization ────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    fetchMitre();
    startPolling();
    initTopologyCanvas();
});

// ── Polling Loop ──────────────────────────────────────────────────
// Initializes a recursive setTimeout loop that fetches the latest state 
// from the backend REST API every 2000ms.
function startPolling() {
    async function poll() {
        try {
            const [statusRes, eventsRes, alertsRes, cacheRes, quarRes, topoRes] =
                await Promise.all([
                    fetch(`${API_BASE}/api/status`),
                    fetch(`${API_BASE}/api/events?limit=200`),
                    fetch(`${API_BASE}/api/alerts`),
                    fetch(`${API_BASE}/api/cache`),
                    fetch(`${API_BASE}/api/quarantine`),
                    fetch(`${API_BASE}/api/topology`),
                ]);

            if (!statusRes.ok) throw new Error("API error");

            // Parse JSON responses into respective state properties
            const status = await statusRes.json();
            const events = await eventsRes.json();
            const alerts = await alertsRes.json();
            const cache = await cacheRes.json();
            const quarantine = await quarRes.json();
            const topology = await topoRes.json();

            // Update the global state object with the newly fetched data
            state.connected = true;
            state.events = events.events || [];
            state.alerts = alerts.alerts || [];
            state.cache = cache.entries || [];
            state.quarantine = quarantine.actions || [];
            state.topology = topology.hosts || [];
            state.stats = status.detection_stats || {};
            state.mode = status.mode || "unknown";

            // Trigger a full re-render of all dashboard components
            updateUI();
            setConnectionStatus("connected", "Connected");

        } catch (err) {
            state.connected = false;
            setConnectionStatus("error", "Disconnected");
        }

        setTimeout(poll, POLL_INTERVAL);
    }
    poll();
}

// ── UI Update Orchestrator ────────────────────────────────────────
function updateUI() {
    updateStats();
    updateArpTable();
    updateAlertFeed();
    updateTimeline();
    updateQuarantineFeed();
    updateTopology();
    updatePhase();
}

// ── Connection Status ─────────────────────────────────────────────
function setConnectionStatus(type, text) {
    const indicator = document.getElementById("connection-status");
    const dot = indicator.querySelector(".status-dot");
    const label = indicator.querySelector(".status-text");
    dot.className = `status-dot ${type}`;
    label.textContent = text;
}

// ── Statistics Cards ──────────────────────────────────────────────
function updateStats() {
    animateCounter("total-events", state.events.length);
    animateCounter("total-alerts", state.alerts.length);

    const quarantinedCount = state.quarantine.filter(
        q => q.status === "applied"
    ).length;
    animateCounter("total-quarantined", quarantinedCount);

    const dt = state.stats.detection_time_sec;
    const dtEl = document.getElementById("detection-time");
    if (dt !== null && dt !== undefined) {
        dtEl.textContent = `${dt}s`;
        dtEl.style.color = dt <= 30
            ? "var(--status-healthy)"
            : "var(--severity-critical)";
    }

    // Update mode badge
    const modeBadge = document.getElementById("topology-mode");
    if (modeBadge && state.mode) {
        modeBadge.textContent = state.mode === "simulation" ? "Simulation" : "Live";
    }
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    const current = parseInt(el.textContent) || 0;
    if (current !== target) {
        el.textContent = target;
        el.style.transform = "scale(1.15)";
        setTimeout(() => el.style.transform = "scale(1)", 200);
    }
}

// ── ARP Binding Table ─────────────────────────────────────────────
function updateArpTable() {
    const tbody = document.getElementById("arp-table-body");
    const sizeEl = document.getElementById("cache-size");

    if (!state.cache.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No entries yet</td></tr>';
        sizeEl.textContent = "0 entries";
        return;
    }

    sizeEl.textContent = `${state.cache.length} entries`;

    const quarantinedSet1 = new Set();
    state.quarantine.forEach(q => {
        if (q.status === "applied") {
            quarantinedSet1.add(q.attacker_mac);
        } else if (q.status === "released") {
            quarantinedSet1.delete(q.attacker_mac);
        }
    });
    const quarantinedMacs = quarantinedSet1;

    tbody.innerHTML = state.cache.map(entry => {
        const isQuarantined = quarantinedMacs.has(entry.mac);
        const isChanged = entry.change_count > 0;
        const rowClass = isQuarantined ? "quarantined" : isChanged ? "changed" : "";

        let statusBadge;
        if (isQuarantined) {
            statusBadge = '<span class="badge badge-quarantined">quarantined</span>';
        } else if (entry.is_trusted) {
            statusBadge = '<span class="badge badge-trusted">trusted</span>';
        } else if (isChanged) {
            statusBadge = '<span class="badge badge-changed">changed</span>';
        } else {
            statusBadge = '<span class="badge badge-normal">normal</span>';
        }

        const vlanBadge = entry.vlan_id === 999
            ? '<span class="badge badge-vlan-quarantine">999</span>'
            : `<span class="badge badge-vlan-normal">${entry.vlan_id}</span>`;

        const lastSeen = entry.last_seen
            ? new Date(entry.last_seen).toLocaleTimeString()
            : "—";

        return `
            <tr class="${rowClass}">
                <td>${entry.ip}</td>
                <td>${entry.mac}</td>
                <td>${statusBadge}</td>
                <td>${entry.change_count}</td>
                <td>${vlanBadge}</td>
                <td>${lastSeen}</td>
            </tr>
        `;
    }).join("");
}

// ── Alert Feed ────────────────────────────────────────────────────
function updateAlertFeed() {
    const feed = document.getElementById("alert-feed");
    const countBadge = document.getElementById("alert-count");
    countBadge.textContent = state.alerts.length;

    if (!state.alerts.length) {
        feed.innerHTML = '<div class="alert-empty">No alerts detected</div>';
        return;
    }

    // Show most recent first, limit to 20
    const recentAlerts = [...state.alerts].reverse().slice(0, 20);

    feed.innerHTML = recentAlerts.map(alert => {
        const sev = alert.severity || "medium";
        const time = alert.timestamp
            ? new Date(alert.timestamp).toLocaleTimeString()
            : "";

        return `
            <div class="alert-item ${sev}">
                <div class="alert-header">
                    <span class="alert-severity ${sev}">${sev}</span>
                    <span class="alert-type">${alert.detection_type || ""}</span>
                </div>
                <div class="alert-desc">${truncate(alert.description, 180)}</div>
                <div class="alert-meta">
                    <span>MAC: ${alert.src_mac || "—"}</span>
                    <span>IP: ${alert.src_ip || "—"}</span>
                    <span>${time}</span>
                    <span>${alert.mitre_technique || ""}</span>
                </div>
            </div>
        `;
    }).join("");
}

// ── Attack Timeline ───────────────────────────────────────────────
function updateTimeline() {
    const timeline = document.getElementById("attack-timeline");

    // Build timeline events from alerts and quarantine actions
    const timelineEvents = [];

    // Add alerts
    state.alerts.forEach(alert => {
        const sev = alert.severity || "medium";
        const dotClass = sev === "critical" ? "critical" : "warning";
        timelineEvents.push({
            time: alert.timestamp,
            title: `${sev.toUpperCase()}: ${alert.detection_type}`,
            desc: truncate(alert.description, 120),
            dotClass: dotClass,
            cardClass: sev === "critical" ? "critical" : "",
        });
    });

    // Add quarantine actions
    state.quarantine.forEach(action => {
        timelineEvents.push({
            time: action.timestamp,
            title: `QUARANTINE ${action.status.toUpperCase()}`,
            desc: `MAC ${action.attacker_mac} moved to VLAN ${action.to_vlan} (port ${action.switch_port})`,
            dotClass: "quarantine",
            cardClass: "quarantine",
        });
    });

    // Sort by time (newest first)
    timelineEvents.sort((a, b) =>
        new Date(b.time || 0) - new Date(a.time || 0)
    );

    if (!timelineEvents.length) {
        timeline.innerHTML = '<div class="timeline-empty">Waiting for events…</div>';
        return;
    }

    // Show latest 15
    timeline.innerHTML = timelineEvents.slice(0, 15).map(evt => {
        const time = evt.time
            ? new Date(evt.time).toLocaleTimeString()
            : "";
        return `
            <div class="timeline-event ${evt.cardClass}">
                <div class="timeline-dot ${evt.dotClass}"></div>
                <div class="timeline-content">
                    <div class="timeline-title">${evt.title}</div>
                    <div class="timeline-desc">${evt.desc}</div>
                </div>
                <div class="timeline-time">${time}</div>
            </div>
        `;
    }).join("");
}

// ── Quarantine Feed ───────────────────────────────────────────────
function updateQuarantineFeed() {
    const feed = document.getElementById("quarantine-feed");

    if (!state.quarantine.length) {
        feed.innerHTML = '<div class="quarantine-empty">No quarantine actions</div>';
        return;
    }

    feed.innerHTML = [...state.quarantine].reverse().map(action => {
        const statusIcon = action.status === "applied" ? "✅" :
                           action.status === "failed" ? "❌" : "⏳";
        const statusClass = action.status;

        return `
            <div class="quarantine-item ${statusClass}">
                <div class="quarantine-title">
                    ${statusIcon} ${action.status.toUpperCase()} — Port ${action.switch_port}
                </div>
                <div class="quarantine-detail">
                    MAC: ${action.attacker_mac}<br>
                    IP: ${action.attacker_ip || "—"}<br>
                    VLAN: ${action.from_vlan} → ${action.to_vlan}<br>
                    Method: ${action.method}<br>
                    Time: ${action.timestamp ? new Date(action.timestamp).toLocaleTimeString() : "—"}
                </div>
            </div>
        `;
    }).join("");
}

// ── Phase Badge ───────────────────────────────────────────────────
function updatePhase() {
    const badge = document.getElementById("phase-badge");
    if (!badge) return;

    const hasAlerts = state.alerts.length > 0;
    const hasQuarantine = state.quarantine.some(q => q.status === "applied");

    if (hasQuarantine) {
        badge.textContent = "Quarantine Active";
        badge.style.background = "rgba(139, 92, 246, 0.2)";
        badge.style.color = "var(--accent-purple)";
    } else if (hasAlerts) {
        badge.textContent = "Attack Detected";
        badge.style.background = "rgba(239, 68, 68, 0.2)";
        badge.style.color = "var(--severity-critical)";
    } else if (state.events.length > 0) {
        badge.textContent = "Monitoring";
        badge.style.background = "rgba(16, 185, 129, 0.15)";
        badge.style.color = "var(--status-healthy)";
    } else {
        badge.textContent = "Initializing";
    }
}

// ── MITRE ATT&CK Info ─────────────────────────────────────────────
async function fetchMitre() {
    try {
        const res = await fetch(`${API_BASE}/api/mitre`);
        if (!res.ok) return;
        const data = await res.json();
        state.mitre = data;

        document.getElementById("mitre-technique").textContent =
            data.technique_id || "T1557.002";
        document.getElementById("mitre-name").textContent =
            data.technique_name || "ARP Cache Poisoning";
        document.getElementById("mitre-tactic").textContent =
            data.tactic || "—";
        document.getElementById("mitre-sources").textContent =
            (data.data_sources || []).join(", ");

        const list = document.getElementById("mitre-mitigation-list");
        list.innerHTML = (data.mitigations || [])
            .map(m => `<li>${m}</li>`)
            .join("");
    } catch (e) {
        // Will retry on next poll cycle
    }
}

// ── Network Topology Canvas ───────────────────────────────────────
let canvas, ctx;
let topoAnimFrame;

function initTopologyCanvas() {
    canvas = document.getElementById("topology-canvas");
    ctx = canvas.getContext("2d");
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);
    drawTopology();
}

function resizeCanvas() {
    const rect = canvas.parentElement.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = 650 * window.devicePixelRatio;
    canvas.style.width = rect.width + "px";
    canvas.style.height = "650px";
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
}

function updateTopology() {
    drawTopology();
}

function drawTopology() {
    if (!ctx) return;
    const w = canvas.width / window.devicePixelRatio;
    const h = canvas.height / window.devicePixelRatio;

    ctx.clearRect(0, 0, w, h);

    // Define host positions
    const quarantinedSet2 = new Set();
    state.quarantine.forEach(q => {
        if (q.status === "applied") {
            quarantinedSet2.add(q.attacker_mac);
        } else if (q.status === "released") {
            quarantinedSet2.delete(q.attacker_mac);
        }
    });
    const quarantinedMacs = quarantinedSet2;

    const hosts = state.topology.length > 0
        ? state.topology
        : [
            { name: "gateway", ip: "192.168.100.1", mac: "02:42:c0:a8:64:01", role: "gateway", port: "Gi0/1" },
            { name: "workstation", ip: "192.168.100.10", mac: "02:42:c0:a8:64:0a", role: "workstation", port: "Gi0/2" },
            { name: "workstation2", ip: "192.168.100.11", mac: "02:42:c0:a8:64:0b", role: "workstation", port: "Gi0/8" },
            { name: "workstation3", ip: "192.168.100.12", mac: "02:42:c0:a8:64:0c", role: "workstation", port: "Gi0/9" },
            { name: "server", ip: "192.168.100.20", mac: "02:42:c0:a8:64:14", role: "server", port: "Gi0/3" },
            { name: "server2", ip: "192.168.100.21", mac: "02:42:c0:a8:64:15", role: "server", port: "Gi0/10" },
            { name: "attacker", ip: "192.168.100.30", mac: "02:42:c0:a8:64:1e", role: "attacker", port: "Gi0/4" },
            { name: "attacker2", ip: "192.168.100.31", mac: "02:42:c0:a8:64:1f", role: "attacker", port: "Gi0/6" },
            { name: "attacker3", ip: "192.168.100.32", mac: "02:42:c0:a8:64:20", role: "attacker", port: "Gi0/7" },
            { name: "monitor", ip: "192.168.100.254", mac: "02:42:c0:a8:64:28", role: "monitor", port: "Gi0/5" },
        ];

    // Position nodes in a network layout (wider and taller)
    const positions = {
        gateway:      { x: w * 0.5,  y: 80 },
        workstation:  { x: w * 0.2,  y: 200 },
        workstation2: { x: w * 0.2,  y: 330 },
        workstation3: { x: w * 0.2,  y: 460 },
        server:       { x: w * 0.4,  y: 570 },
        server2:      { x: w * 0.6,  y: 570 },
        attacker:     { x: w * 0.8,  y: 200 },
        attacker2:    { x: w * 0.8,  y: 330 },
        attacker3:    { x: w * 0.8,  y: 460 },
        monitor:      { x: w * 0.5,  y: 190 },
    };

    // Draw switch in center
    const switchPos = { x: w * 0.5, y: 330 };
    drawSwitch(switchPos.x, switchPos.y);

    // Draw connections and nodes
    hosts.forEach(host => {
        const pos = positions[host.name] || positions[host.role] || { x: w * 0.5, y: h * 0.5 };
        const isQuarantined = quarantinedMacs.has(host.mac) || host.is_quarantined;

        // Draw connection to switch
        drawConnection(switchPos.x, switchPos.y, pos.x, pos.y, isQuarantined, host.port);

        // Draw the host node
        drawHostNode(pos.x, pos.y, host, isQuarantined);
    });

    // Draw attack arrow if there are alerts
    if (state.alerts.length > 0 && positions.attacker && positions.gateway) {
        const isQ = quarantinedMacs.size > 0;
        if (!isQ) {
            drawAttackArrow(
                positions.attacker.x, positions.attacker.y,
                positions.workstation.x, positions.workstation.y
            );
        }
    }
}

function drawSwitch(x, y) {
    ctx.save();
    // Switch box
    const sw = 80, sh = 30;
    ctx.fillStyle = "rgba(59, 130, 246, 0.15)";
    ctx.strokeStyle = "rgba(59, 130, 246, 0.4)";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.roundRect(x - sw/2, y - sh/2, sw, sh, 6);
    ctx.fill();
    ctx.stroke();

    // Label
    ctx.fillStyle = "#60a5fa";
    ctx.font = "500 11px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("SWITCH", x, y);
    ctx.restore();
}

function drawConnection(x1, y1, x2, y2, isQuarantined, portName) {
    ctx.save();
    ctx.strokeStyle = isQuarantined
        ? "rgba(239, 68, 68, 0.3)"
        : "rgba(148, 163, 184, 0.15)";
    ctx.lineWidth = isQuarantined ? 2 : 1;
    if (isQuarantined) {
        ctx.setLineDash([5, 5]);
    }
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();

    if (portName) {
        const mx = x1 + (x2 - x1) * 0.25;
        const my = y1 + (y2 - y1) * 0.25;
        ctx.font = "9px 'JetBrains Mono', monospace";
        const tw = ctx.measureText(portName).width + 8;
        ctx.fillStyle = "rgba(15, 23, 42, 0.8)";
        ctx.fillRect(mx - tw/2, my - 7, tw, 14);
        
        ctx.fillStyle = "#94a3b8";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(portName, mx, my);
    }
    ctx.restore();
}

function drawHostNode(x, y, host, isQuarantined) {
    ctx.save();
    const radius = 22;

    // Glow effect
    if (isQuarantined) {
        ctx.shadowColor = "rgba(239, 68, 68, 0.4)";
        ctx.shadowBlur = 15;
    } else if (host.role === "attacker" || host.name === "attacker") {
        ctx.shadowColor = "rgba(249, 115, 22, 0.3)";
        ctx.shadowBlur = 10;
    } else if (host.role === "gateway" || host.name === "gateway") {
        ctx.shadowColor = "rgba(59, 130, 246, 0.3)";
        ctx.shadowBlur = 10;
    }

    // Circle
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);

    if (isQuarantined) {
        ctx.fillStyle = "rgba(239, 68, 68, 0.2)";
        ctx.strokeStyle = "rgba(239, 68, 68, 0.6)";
    } else if (host.role === "attacker" || host.name === "attacker") {
        ctx.fillStyle = "rgba(249, 115, 22, 0.15)";
        ctx.strokeStyle = "rgba(249, 115, 22, 0.5)";
    } else if (host.role === "gateway" || host.name === "gateway") {
        ctx.fillStyle = "rgba(59, 130, 246, 0.15)";
        ctx.strokeStyle = "rgba(59, 130, 246, 0.5)";
    } else {
        ctx.fillStyle = "rgba(16, 185, 129, 0.12)";
        ctx.strokeStyle = "rgba(16, 185, 129, 0.4)";
    }

    ctx.lineWidth = 2;
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Icon
    const icons = {
        gateway: "🌐",
        workstation: "💻",
        server: "🖥️",
        attacker: isQuarantined ? "🔒" : "☠️",
        monitor: "🛡️",
    };
    const icon = icons[host.role || host.name] || "📡";
    ctx.font = "16px serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(icon, x, y - 1);

    // Name label
    ctx.fillStyle = "#e2e8f0";
    ctx.font = "600 10px Inter, sans-serif";
    ctx.fillText(host.name || host.role, x, y + radius + 14);

    // IP label
    ctx.fillStyle = "#64748b";
    ctx.font = "9px 'JetBrains Mono', monospace";
    ctx.fillText(host.ip, x, y + radius + 26);

    // MAC label
    ctx.fillStyle = "#475569";
    ctx.font = "8px 'JetBrains Mono', monospace";
    ctx.fillText(host.mac || "—", x, y + radius + 36);

    // VLAN label
    const vlanText = "VLAN: " + (host.vlan !== undefined ? host.vlan : (isQuarantined ? 999 : 1));
    ctx.fillStyle = isQuarantined ? "#ef4444" : "#3b82f6";
    ctx.font = "bold 8px Inter, sans-serif";
    ctx.fillText(vlanText, x, y + radius + 46);

    // Quarantine badge
    if (isQuarantined) {
        ctx.font = "bold 8px Inter, sans-serif";
        const textWidth = ctx.measureText("QUARANTINED").width;
        ctx.fillStyle = "rgba(239, 68, 68, 0.9)";
        ctx.fillRect(x - textWidth/2 - 4, y + radius + 52, textWidth + 8, 14);
        
        ctx.fillStyle = "#ffffff";
        ctx.fillText("QUARANTINED", x, y + radius + 62);
    }

    ctx.restore();
}

function drawAttackArrow(x1, y1, x2, y2) {
    ctx.save();
    const t = Date.now() / 600;
    const alpha = 0.3 + 0.3 * Math.sin(t);

    ctx.strokeStyle = `rgba(239, 68, 68, ${alpha})`;
    ctx.lineWidth = 2;
    ctx.setLineDash([8, 6]);

    // Draw the attack line
    ctx.beginPath();
    ctx.moveTo(x1, y1);
    ctx.lineTo(x2, y2);
    ctx.stroke();

    // Attack label at midpoint
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    ctx.fillStyle = `rgba(239, 68, 68, ${alpha + 0.3})`;
    ctx.font = "bold 9px Inter, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("⚡ ARP SPOOF", mx, my - 8);

    ctx.restore();

    // Request animation frame for the pulsing effect
    if (state.alerts.length > 0) {
        requestAnimationFrame(() => drawTopology());
    }
}

// ── Utilities ─────────────────────────────────────────────────────
function truncate(str, max) {
    if (!str) return "";
    return str.length > max ? str.slice(0, max) + "…" : str;
}
