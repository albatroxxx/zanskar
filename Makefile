BINARY   := zanskar
MODULE   := github.com/albatroxxx/zanskar
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)

.PHONY: all build build-api web web-dev dist-linux notices run test lint vet vuln sec tidy clean migrate-check

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

# notices regenerates the third-party license/attribution file. Run it after
# changing Go or npm dependencies; CI fails if the committed file is stale.
notices:
	bash hack/gen-notices.sh > THIRD_PARTY_NOTICES.md

# dist-linux builds the linux/amd64 binary and packages it as a release archive
# carrying the files a distribution must include: the project license, the
# bundled-asset list, and the third-party notices (verified current by CI).
STAGE := zanskar-$(VERSION)-linux-amd64
dist-linux: web
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags webui -ldflags '$(LDFLAGS)' -o dist/zanskar-linux-amd64 ./cmd/zanskar
	rm -rf dist/stage && mkdir -p dist/stage/$(STAGE)
	cp dist/zanskar-linux-amd64 dist/stage/$(STAGE)/zanskar
	cp LICENSE THIRD_PARTY_LICENSES.md THIRD_PARTY_NOTICES.md dist/stage/$(STAGE)/
	tar -C dist/stage -czf dist/$(STAGE).tar.gz $(STAGE)
	rm -rf dist/stage
	cd dist && (sha256sum $(STAGE).tar.gz 2>/dev/null || shasum -a 256 $(STAGE).tar.gz) > $(STAGE).tar.gz.sha256
