# Makefile for Aegis (Source & Docker)

.PHONY: run build clean docker-build updater admin-build admin-typecheck admin-verify

VERSION ?= dev
BUILD_DATE ?= unknown
BUILD_TAGS ?=
LDFLAGS = -s -w -X github.com/divinelab-io/aegis/internal/core/admin.Version=$(VERSION) -X github.com/divinelab-io/aegis/internal/core/admin.BuildDate=$(BUILD_DATE) -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE)

build:
	mkdir -p bin
	go build -trimpath -tags "$(BUILD_TAGS)" -ldflags "$(LDFLAGS)" -o bin/aegis ./cmd/aegis-server
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/aegis-updater ./cmd/aegis-updater
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/aegisctl ./cmd/aegisctl

updater:
	go run ./cmd/aegis-updater all --config config.yaml

# Default: Run from source (Cross-platform compatible via Go)
run:
	go run -tags "$(BUILD_TAGS)" ./cmd/aegis-server

# Docker Build (Linux Container)
docker-build:
	docker build -t aegis-waf .

# Clean compiled artifacts (if any)
clean:
	rm -rf bin/

admin-build:
	npm run admin:build

admin-typecheck:
	npm run admin:typecheck

admin-verify:
	npm run admin:verify

# Infrastructure Management
infra-up:
	@echo "Starting Infrastructure (Postgres + Redis)..."
	@docker compose up -d

infra-down:
	@echo "Stopping Infrastructure..."
	@docker compose down

db-shell:
	@echo "Connecting to Postgres..."
	@docker compose exec postgres psql -U aegis -d aegis

redis-shell:
	@echo "Connecting to Redis..."
	@docker compose exec redis redis-cli
