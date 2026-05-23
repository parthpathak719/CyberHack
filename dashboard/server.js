/**
 * ARP Guardian — Dashboard API Server (Node.js)
 *
 * Serves the static dashboard files and proxies API requests
 * to the Python ARP Guardian REST API on port 8081.
 *
 * Usage:
 *   node dashboard/server.js
 *   → Dashboard at http://localhost:8080
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.DASHBOARD_PORT || 8080;
const API_BACKEND = process.env.API_BACKEND || "http://localhost:8081";

// MIME types for static files
const MIME_TYPES = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "application/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

const DASHBOARD_DIR = __dirname;

const server = http.createServer((req, res) => {
  // ── API proxy ─────────────────────────────────────────────────
  if (req.url.startsWith("/api/")) {
    const backendUrl = new URL(req.url, API_BACKEND);
    const proxyReq = http.request(backendUrl, { method: req.method }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, {
        "Content-Type": proxyRes.headers["content-type"] || "application/json",
        "Access-Control-Allow-Origin": "*",
      });
      proxyRes.pipe(res);
    });
    proxyReq.on("error", () => {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        error: "Backend not reachable",
        hint: "Start the ARP Guardian: python -m src.arp_guardian --simulate",
      }));
    });
    req.pipe(proxyReq);
    return;
  }

  // ── Static files ──────────────────────────────────────────────
  let filePath = req.url === "/" ? "/index.html" : req.url;
  filePath = path.join(DASHBOARD_DIR, filePath);

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || "application/octet-stream";

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end("<h1>404 — Not Found</h1>");
      return;
    }
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log();
  console.log("╔══════════════════════════════════════════════════╗");
  console.log("║        🛡️  ARP Guardian Dashboard                ║");
  console.log(`║        http://localhost:${PORT}                    ║`);
  console.log("╚══════════════════════════════════════════════════╝");
  console.log();
  console.log(`  API backend: ${API_BACKEND}`);
  console.log(`  Serving from: ${DASHBOARD_DIR}`);
  console.log();
});
