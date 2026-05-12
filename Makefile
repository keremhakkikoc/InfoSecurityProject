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
        lint-bandit lint-ruff format ci ca-init ca-issue clean

help:
	@echo "Targets:"
	@echo "  install         pip install runtime requirements"
	@echo "  install-dev     pip install runtime + dev requirements (bandit, ruff, cov)"
	@echo "  test            run pytest"
	@echo "  test-cov        run pytest with coverage report"
	@echo "  lint            run ALL lint checks (forbidden + frozen + bandit + ruff)"
	@echo "  lint-forbidden  check banned imports (AI.md §1.11, etc.)"
	@echo "  lint-frozen     check frozen signatures (ARCHITECTURE.md §10.1)"
	@echo "  lint-bandit     security linter (bandit)"
	@echo "  lint-ruff       style linter (ruff check)"
	@echo "  format          auto-format with ruff format"
	@echo "  ci              full CI sweep locally (test + lint)"
	@echo "  ca-init         bootstrap CA (writes ca_data/)"
	@echo "  ca-issue        issue cert: make ca-issue USER=alice"
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

clean:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .coverage htmlcov
	rm -rf ca_data users
