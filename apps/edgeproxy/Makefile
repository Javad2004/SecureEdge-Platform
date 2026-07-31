.PHONY: build test run run-origin validate fmt vet clean

build:
	mkdir -p bin
	go build -trimpath -o bin/edgeproxy ./cmd/edgeproxy
	go build -trimpath -o bin/origin-demo ./cmd/origin-demo

test:
	go test -race ./...

run:
	go run ./cmd/edgeproxy -config configs/local-dev.json -pretty-logs

run-origin:
	go run ./cmd/origin-demo -listen :9000 -name origin-a

validate:
	go run ./cmd/edgeproxy -config configs/local-dev.json -validate

fmt:
	gofmt -w $$(find . -name '*.go')

vet:
	go vet ./...

clean:
	rm -rf bin coverage.out
