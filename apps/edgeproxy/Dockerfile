FROM golang:1.23-alpine AS build

WORKDIR /src

COPY go.mod ./
COPY . ./

RUN CGO_ENABLED=0 go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/edgeproxy ./cmd/edgeproxy \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/origin-demo ./cmd/origin-demo

FROM alpine:3.21 AS origin-demo

RUN apk add --no-cache ca-certificates \
 && addgroup -S origin \
 && adduser -S -G origin origin

COPY --from=build /out/origin-demo /usr/local/bin/origin-demo

USER origin
EXPOSE 9000

HEALTHCHECK --interval=5s --timeout=2s --start-period=3s --retries=10 \
  CMD wget -q -O /dev/null http://127.0.0.1:9000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/origin-demo"]
CMD ["-listen", "0.0.0.0:9000", "-name", "origin-compose"]

FROM alpine:3.21 AS edgeproxy

RUN apk add --no-cache ca-certificates \
 && addgroup -S edgeproxy \
 && adduser -S -G edgeproxy edgeproxy

WORKDIR /app

COPY --from=build /out/edgeproxy /usr/local/bin/edgeproxy
COPY configs/compose.json /app/config.json

USER edgeproxy
EXPOSE 8080 9090

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:9090/readyz || exit 1

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/edgeproxy"]
CMD ["-config", "/app/config.json"]
