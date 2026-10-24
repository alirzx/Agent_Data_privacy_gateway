.PHONY: setup dev api ui test lint format docker-up docker-down docs-example
PYTHON ?= python3

setup:
	$(PYTHON) scripts/init_dev_env.py

api:
	cd backend && set -a && . ../.env && set +a && PYTHONPATH=. uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8484 --reload

ui:
	cd frontend && npm run dev

dev:
	@echo 'Run make api in one terminal and make ui in another.'

test:
	cd backend && PYTHONPATH=. $(PYTHON) -m pytest -q

lint:
	cd backend && PYTHONPATH=. $(PYTHON) -m ruff check app tests

format:
	cd backend && $(PYTHON) -m ruff format app tests

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docs-example:
	@echo 'curl -fsS http://127.0.0.1:8484/health'
