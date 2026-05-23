import os
import sys
import http.server
import urllib.request
import urllib.error

PORT = int(os.environ.get("DASHBOARD_PORT", 8080))
API_BACKEND = os.environ.get("API_BACKEND", "http://localhost:8081")

class ProxyAndStaticHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/"):
            self.proxy_request("GET")
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self.proxy_request("POST")
        else:
            self.send_error(405, "Method not allowed")

    def do_OPTIONS(self):
        if self.path.startswith("/api/"):
            self.proxy_request("OPTIONS")
        else:
            super().do_OPTIONS()

    def proxy_request(self, method):
        url = API_BACKEND + self.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        req = urllib.request.Request(
            url, 
            data=body, 
            headers={k: v for k, v in self.headers.items() if k.lower() != 'host'},
            method=method
        )
        try:
            with urllib.request.urlopen(req) as response:
                self.send_response(response.status)
                for k, v in response.getheaders():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(response.read())
        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            import json
            self.wfile.write(json.dumps({
                "error": "Backend not reachable",
                "hint": "Start the ARP Guardian: python -m src.arp_guardian --simulate"
            }).encode())

if __name__ == "__main__":
    DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
    os.chdir(DASHBOARD_DIR)
    
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║        🛡️  ARP Guardian Dashboard (Python)        ║")
    print(f"║        http://localhost:{PORT}                    ║")
    print("╚══════════════════════════════════════════════════╝")
    print()
    print(f"  API backend: {API_BACKEND}")
    print(f"  Serving from: {DASHBOARD_DIR}")
    print()
    try:
        http.server.HTTPServer(("0.0.0.0", PORT), ProxyAndStaticHTTPRequestHandler).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
