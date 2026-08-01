VERSION ?= development
COMMIT ?= $$(git rev-parse --short HEAD 2>/dev/null || echo development)
BUILD_TIME ?= $$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version.Version=$(VERSION) -X github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version.Commit=$(COMMIT) -X github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: fmt fmt-check test race vet js build verify run run-network validate validate-network validate-compose clean

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -type f))" || (echo "Go files require gofmt:"; gofmt -l $$(find . -name '*.go' -type f); exit 1)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

js:
	node --check internal/admin/web/app.js

build:
	mkdir -p bin
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/securityedge ./cmd/securityedge

validate:
	go run ./cmd/securityedge -config configs/local-dev.json -validate

validate-network:
	go run ./cmd/securityedge -config configs/securityedge.json -validate

validate-compose:
	go run ./cmd/securityedge -config configs/compose.json -validate

verify: fmt-check test race vet js build validate validate-network validate-compose

run:
	go run ./cmd/securityedge -config configs/local-dev.json -pretty-logs

run-network:
	go run ./cmd/securityedge -config configs/securityedge.json -pretty-logs

clean:
	rm -rf bin
	@if [ -d logs ]; then find logs -type f ! -name .gitkeep -delete; fi
