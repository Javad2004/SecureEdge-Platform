.PHONY: build test race run run-origin validate fmt fmt-check vet verify clean

build:
	mkdir -p bin
	go build -trimpath -o bin/edgeproxy ./cmd/edgeproxy
	go build -trimpath -o bin/origin-demo ./cmd/origin-demo

test:
	go test ./...

race:
	go test -race ./...

run:
	go run ./cmd/edgeproxy -config configs/local-dev.json -pretty-logs

run-origin:
	go run ./cmd/origin-demo -listen 127.0.0.1:9000 -name origin-local

validate:
	go run ./cmd/edgeproxy -config configs/local-dev.json -validate

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

fmt-check:
	@test -z "$$(gofmt -l $$(find . -name '*.go' -type f))" || (echo "Go files require gofmt:"; gofmt -l $$(find . -name '*.go' -type f); exit 1)

vet:
	go vet ./...

verify: fmt-check vet test race build validate

clean:
	rm -rf bin coverage.out
