.PHONY: dev down build migrate sqlc lint test help

# Default target
help:
	@echo "DevSecOps Platform"
	@echo ""
	@echo "  make dev        - Start all services with Docker Compose"
	@echo "  make down       - Stop all services"
	@echo "  make build      - Build all Docker images"
	@echo "  make migrate    - Run database migrations"
	@echo "  make sqlc       - Generate sqlc code"
	@echo "  make lint       - Run linters (Go + JS)"
	@echo "  make test       - Run all tests"
	@echo "  make logs       - Tail all service logs"

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

migrate-create:
	@read -p "Migration name: " name; \
	docker compose run --rm backend go run ./cmd/migrate create -ext sql -dir ./internal/db/migrations -seq $$name

.env:
	cp .env.example .env
