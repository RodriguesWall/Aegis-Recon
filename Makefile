.PHONY: build cli api seed test vet fmt fmtcheck ci clean

BIN := bin

# Version injected at link time. Falls back to "dev" outside a git checkout.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/RodriguesWall/aegis-recon/internal/version.Version=$(VERSION)

build: cli api

cli:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/aegis ./cmd/aegis

api:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/aegisd ./cmd/aegisd

# Populate the DB with demo data (fake domains) for screenshots. Run on a fresh
# DB, then start the app. Override the path with AEGIS_DB=...
seed:
	go run ./cmd/seed

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmtcheck:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

ci: fmtcheck vet test

clean:
	rm -rf $(BIN)
