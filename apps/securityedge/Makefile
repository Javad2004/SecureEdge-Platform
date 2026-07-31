.PHONY: fmt test race vet build verify run validate

fmt:
	gofmt -w .

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

build:
	go build ./cmd/securityedge

verify: fmt test race vet build

run:
	go run ./cmd/securityedge -config configs/local-dev.json -pretty-logs

validate:
	go run ./cmd/securityedge -config configs/local-dev.json -validate
