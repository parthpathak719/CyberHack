# ──────────────────────────────────────────────────────────────────
# ARP Guardian — Makefile
# ──────────────────────────────────────────────────────────────────

.PHONY: help install simulate live docker docker-down dashboard test clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## Install Python dependencies
	pip install -r requirements.txt

simulate:  ## Run in simulation mode (no root needed)
	python -m src.arp_guardian --simulate --switch-url http://localhost:5000

live:  ## Run in live capture mode (requires sudo)
	sudo python -m src.arp_guardian --iface en0

dashboard:  ## Start the dashboard server (falls back to Python if Node is missing)
	@if command -v node >/dev/null 2>&1; then \
		node dashboard/server.js; \
	else \
		echo "⚠️  Node.js not found, falling back to Python server..."; \
		python3 dashboard/server.py; \
	fi

switch:  ## Start the simulated switch API
	python switch_simulator/app.py

docker:  ## Build and start all Docker containers
	docker-compose up --build -d

docker-down:  ## Stop all Docker containers
	docker-compose down

docker-attack:  ## Launch ARP spoofing attack in Docker
	docker exec arp-attacker python /app/arp_spoof.py \
		--target 192.168.100.10 --gateway 192.168.100.1 \
		--interface eth0 --interval 0.5

docker-logs:  ## Follow monitor logs
	docker logs -f arp-monitor

test:  ## Run unit tests
	python -m pytest tests/ -v --tb=short

clean:  ## Remove generated data files
	rm -rf data/*.json data/*.log __pycache__ .pytest_cache
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

demo: install switch-bg simulate  ## Run full demo (switch + monitor in simulation mode)

switch-bg:  ## Start switch in background
	@echo "Starting switch simulator in background..."
	python switch_simulator/app.py &
	sleep 2
