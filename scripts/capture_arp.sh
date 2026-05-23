#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# Wireshark Validation Script
#
# Captures ARP traffic for Wireshark analysis to validate detection.
#
# Usage:
#   chmod +x scripts/capture_arp.sh
#   sudo ./scripts/capture_arp.sh
#
# Output: data/arp_capture.pcap
# Open in Wireshark: wireshark data/arp_capture.pcap
# Filter: arp
# ──────────────────────────────────────────────────────────────────

set -euo pipefail

IFACE="${1:-eth0}"
DURATION="${2:-60}"
OUTPUT="data/arp_capture.pcap"

mkdir -p data

echo "🦈 Capturing ARP traffic on ${IFACE} for ${DURATION}s..."
echo "   Output: ${OUTPUT}"
echo "   Press Ctrl+C to stop early."
echo ""

# Use tcpdump to capture ARP packets
sudo tcpdump -i "$IFACE" -w "$OUTPUT" -c 1000 arp &
TCPDUMP_PID=$!

sleep "$DURATION" || true
kill $TCPDUMP_PID 2>/dev/null || true

echo ""
echo "✅ Capture saved to ${OUTPUT}"
echo "   Open with: wireshark ${OUTPUT}"
echo "   Filter: arp"
