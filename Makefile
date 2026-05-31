# Convenience targets for humans and AI assistants.
# Run `make help` to see what's available.
#
# Used by:
#   - human contributors (M2/M3 paralel iş)
#   - CI workflows (see .github/workflows/ci.yml)
#   - AI coding assistants (Claude, Copilot, Cursor) — they read this file
#     to find the canonical commands instead of guessing.

PYTHON ?= python
PIP    ?= pip

# All targets are phony — none of these produce a file with the same name.
.PHONY: help install install-dev test test-cov lint lint-forbidden lint-frozen \
        lint-bandit lint-ruff format ci ca-init ca-issue client-setup \
        server-register inspect clean server webui user demo-setup

help:
	@echo "Targets:"
	@echo "  install         pip install runtime requirements"
	@echo "  install-dev     pip install runtime + dev requirements (bandit, ruff, cov)"
	@echo "  test            run pytest"
	@echo "  test-cov        run pytest with coverage report"
	@echo "  lint            run ALL lint checks (forbidden + frozen + bandit + ruff)"
	@echo "  lint-forbidden  check banned imports"
	@echo "  lint-frozen     check frozen signatures (ARCHITECTURE.md §10.1)"
	@echo "  lint-bandit     security linter (bandit)"
	@echo "  lint-ruff       style linter (ruff check)"
	@echo "  format          auto-format with ruff format"
	@echo "  ci              full CI sweep locally (test + lint)"
	@echo "  ca-init         bootstrap CA (writes ca_data/)"
	@echo "  ca-issue        issue cert: make ca-issue USER=alice"
	@echo "  client-setup    build client_<user>/ bundle: make client-setup USER=alice"
	@echo "  server-register register user's pubkey with server: make server-register USER=alice"
	@echo "  inspect         dump server storage: registered users, file rows, ciphertext blobs"
	@echo "  server          run zerotrust.server.main in foreground (Ctrl+C to stop)"
	@echo "  webui           run the Flask demo UI on http://127.0.0.1:8000"
	@echo "  user            full user bootstrap: make user USER=charlie (ca-issue + client-setup + server-register)"
	@echo "  demo-setup      one-shot reset: clean + ca-init + server cert + alice + bob"
	@echo "  clean           remove caches, __pycache__, generated keys/certs"

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements.txt -r requirements-dev.txt

test:
	$(PYTHON) -m pytest

test-cov:
	$(PYTHON) -m pytest --cov=zerotrust --cov-report=term-missing

lint: lint-forbidden lint-frozen lint-bandit lint-ruff

lint-forbidden:
	$(PYTHON) scripts/check_forbidden_imports.py

lint-frozen:
	$(PYTHON) scripts/check_frozen_signatures.py

lint-bandit:
	$(PYTHON) -m bandit -q -r zerotrust -c .bandit.yml

lint-ruff:
	$(PYTHON) -m ruff check zerotrust scripts

format:
	$(PYTHON) -m ruff format zerotrust scripts
	$(PYTHON) -m ruff check --fix zerotrust scripts

ci: test lint

ca-init:
	$(PYTHON) -m zerotrust.ca.ca init

ca-issue:
	@if [ -z "$(USER)" ]; then \
	    echo "Usage: make ca-issue USER=<name>"; exit 2; \
	fi
	$(PYTHON) -m zerotrust.ca.ca issue $(USER)

# Assemble a client_<user>/ deployment bundle from the CA-issued assets
# (users/<user>/) plus the CA trust anchor (ca_data/). Idempotent — re-running
# overwrites the bundle with the current sources.
client-setup:
	@if [ -z "$(USER)" ]; then \
	    echo "Usage: make client-setup USER=<name>"; exit 2; \
	fi
	@if [ ! -f "users/$(USER)/cert.json" ] || [ ! -f "users/$(USER)/private.pem" ]; then \
	    echo "Missing users/$(USER)/{cert.json,private.pem}. Run 'make ca-issue USER=$(USER)' first."; exit 2; \
	fi
	@if [ ! -f "ca_data/ca_cert.json" ]; then \
	    echo "Missing ca_data/ca_cert.json. Run 'make ca-init' first."; exit 2; \
	fi
	mkdir -p client_$(USER)
	cp users/$(USER)/cert.json   client_$(USER)/cert.json
	cp users/$(USER)/private.pem client_$(USER)/private.pem
	cp ca_data/ca_cert.json      client_$(USER)/ca_cert.json
	@printf '{\n  "username": "$(USER)",\n  "server_host": "127.0.0.1",\n  "server_port": 5050,\n  "server_subject": "server"\n}\n' > client_$(USER)/config.json
	@echo "Client bundle ready: client_$(USER)/"

# Register USER's CA-signed cert in the server's pubkey directory so recipient
# lookups (GET_PUBKEY, UPLOAD_REQUEST recipient existence check) succeed.
# Idempotent.
server-register:
	@if [ -z "$(USER)" ]; then \
	    echo "Usage: make server-register USER=<name>"; exit 2; \
	fi
	@if [ ! -f "users/$(USER)/cert.json" ]; then \
	    echo "Missing users/$(USER)/cert.json. Run 'make ca-issue USER=$(USER)' first."; exit 2; \
	fi
	mkdir -p zerotrust/server/storage/pubkeys
	cp users/$(USER)/cert.json zerotrust/server/storage/pubkeys/$(USER).json
	@echo "Registered '$(USER)' in server pubkey directory."

# Quick read-only peek into the server's storage area: which users are
# registered, which file rows exist, and the on-disk ciphertext blobs.
# Useful for "did the upload actually land?" sanity checks during demos.
inspect:
	@echo "=== Registered pubkeys (zerotrust/server/storage/pubkeys/) ==="
	@ls -1 zerotrust/server/storage/pubkeys/ 2>/dev/null || echo "  (none yet — run 'make server-register USER=<name>')"
	@echo ""
	@echo "=== File metadata rows (zerotrust/server/storage/metadata.db) ==="
	@if [ -f zerotrust/server/storage/metadata.db ]; then \
	    sqlite3 -header -column zerotrust/server/storage/metadata.db \
	      "SELECT file_id, sender_id, recipient_id, status, upload_timestamp, expiration FROM files;"; \
	    echo ""; \
	    echo "Row count:"; \
	    sqlite3 zerotrust/server/storage/metadata.db "SELECT COUNT(*) FROM files;"; \
	else \
	    echo "  (no DB yet — run an upload first)"; \
	fi
	@echo ""
	@echo "=== Ciphertext blobs (zerotrust/server/storage/files/) ==="
	@ls -lh zerotrust/server/storage/files/ 2>/dev/null || echo "  (none yet)"

clean:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
	rm -rf ca_data users client_*
	rm -rf zerotrust/server/storage server/storage
	rm -rf webui/.uploads

# Foreground runners. Use separate terminals (or `&` if you know what you're
# doing — the demo UI in webui/ assumes the server is already up).
server:
	$(PYTHON) -m zerotrust.server.main

webui:
	$(PYTHON) webui/app.py

# One-shot user bootstrap: cert, client bundle, and server pubkey registration.
# Idempotent — re-running an existing user just refreshes the bundle.
user:
	@if [ -z "$(USER)" ]; then \
	    echo "Usage: make user USER=<name>"; exit 2; \
	fi
	$(MAKE) ca-issue       USER=$(USER)
	$(MAKE) client-setup   USER=$(USER)
	$(MAKE) server-register USER=$(USER)

# Hard reset + full bootstrap for the 11-step PDF demo. Leaves you ready to
# `make server` in one terminal and `make webui` (or the CLI) in another.
demo-setup:
	$(MAKE) clean
	$(MAKE) ca-init
	$(MAKE) ca-issue USER=server
	$(MAKE) user USER=alice
	$(MAKE) user USER=bob
