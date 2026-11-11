.PHONY: build cli api test vet fmt fmtcheck ci clean

BIN := bin

build: cli api

cli:
	go build -o $(BIN)/aegis ./cmd/aegis

api:
	go build -o $(BIN)/aegisd ./cmd/aegisd

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
