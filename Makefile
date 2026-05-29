export GOTOOLCHAIN := auto

.PHONY: dev down build migrate sqlc lint test help pre-commit pre-push security-check install-hooks

# Default target
help:
	@echo "DevSecOps Platform"
	@echo ""
	@echo "  make dev            - Start all services with Docker Compose"
	@echo "  make down           - Stop all services"
	@echo "  make build          - Build all Docker images"
	@echo "  make migrate        - Run database migrations"
	@echo "  make sqlc           - Generate sqlc code"
	@echo "  make lint           - Run linters (Go + JS)"
	@echo "  make test           - Run all tests"
	@echo "  make pre-commit     - Fast checks (git pre-commit hook)"
	@echo "  make pre-push       - CI parity before push (git pre-push hook)"
	@echo "  make security-check - Optional security workflow parity"
	@echo "  make install-hooks  - Install .githooks/ via core.hooksPath"
	@echo "  make logs           - Tail all service logs"

dev:
	@cp -n .env.example .env 2>/dev/null || true
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

migrate:
	docker compose run --rm backend go run ./cmd/migrate up

sqlc:
	cd backend && sqlc generate

lint:
	cd backend && golangci-lint run ./...
	cd frontend && npm run lint

test:
	cd backend && go test ./...
	cd frontend && npm run test

# Fast feedback — mirrors security.yml lint jobs + go vet + staged secret scan.
pre-commit: require-frontend-deps require-golangci-lint
	@echo "==> Backend: go vet"
	cd backend && go vet ./...
	@echo "==> Backend: golangci-lint"
	cd backend && golangci-lint run ./...
	@echo "==> Frontend: ESLint"
	cd frontend && npm run lint
	@echo "==> Frontend: TypeScript"
	cd frontend && node_modules/.bin/tsc --noEmit
	@echo "==> Secrets: gitleaks (staged)"
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks protect --staged --verbose; \
	else \
		echo "SKIP: gitleaks not installed (brew install gitleaks)"; \
	fi

# CI parity — mirrors ci.yml backend + frontend jobs + security.yml govulncheck.
pre-push: require-frontend-deps
	@echo "==> Backend: build"
	cd backend && go build ./...
	@echo "==> Backend: test"
	cd backend && go test ./...
	@echo "==> Backend: vet"
	cd backend && go vet ./...
	@echo "==> Backend: govulncheck"
	cd backend && bash ../.github/scripts/run-govulncheck.sh
	@echo "==> Frontend: TypeScript"
	cd frontend && node_modules/.bin/tsc --noEmit
	@echo "==> Frontend: test"
	cd frontend && npm run test -- --run

# Optional — mirrors remaining security.yml jobs (OSV, licenses, Semgrep).
security-check:
	bash scripts/security-check.sh

install-hooks:
	bash scripts/install-git-hooks.sh

require-frontend-deps:
	@test -d frontend/node_modules || (echo "Run: cd frontend && npm ci" && exit 1)

require-golangci-lint:
	@command -v golangci-lint >/dev/null || (echo "Install golangci-lint v2.11.4: https://golangci-lint.run/welcome/install/" && exit 1)

migrate-create:
	@read -p "Migration name: " name; \
	docker compose run --rm backend go run ./cmd/migrate create -ext sql -dir ./internal/db/migrations -seq $$name

.env:
	cp .env.example .env
