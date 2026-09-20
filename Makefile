BINARY   := zanskar
MODULE   := github.com/albatroxxx/zanskar
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

.PHONY: all build build-api web web-dev run test lint vet vuln sec tidy clean migrate-check

all: lint test build

build: web
	CGO_ENABLED=0 go build -trimpath -tags webui -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/zanskar

build-api:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/zanskar

web:
	cd web && npm ci --ignore-scripts --no-fund --no-audit && npm run build

web-dev:
	cd web && npm run dev

run:
	go run ./cmd/zanskar serve

test:
	go test -race -cover ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

sec:
	gosec -quiet ./...

tidy:
	go mod tidy

migrate-check:
	@diff <(ls migrations/postgres) <(ls migrations/sqlite) && echo "migration sets match"

clean:
	rm -rf bin/ dist/ coverage.out
