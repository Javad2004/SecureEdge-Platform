VERSION ?= 3.3.0-professional-traffic
COMMIT ?= $$(git rev-parse --short HEAD 2>/dev/null || echo development)
BUILD_TIME ?= $$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X github.com/bachelor-project/edgeproxy-security/internal/version.Version=$(VERSION) -X github.com/bachelor-project/edgeproxy-security/internal/version.Commit=$(COMMIT) -X github.com/bachelor-project/edgeproxy-security/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: fmt test race vet js build verify run run-network validate validate-network clean

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

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

verify: fmt test race vet js build validate validate-network

run:
	go run ./cmd/securityedge -config configs/local-dev.json -pretty-logs

run-network:
	go run ./cmd/securityedge -config configs/securityedge.json -pretty-logs

clean:
	rm -rf bin logs
