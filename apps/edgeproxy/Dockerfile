FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/edgeproxy ./cmd/edgeproxy

FROM alpine:3.20
RUN addgroup -S edgeproxy && adduser -S -G edgeproxy edgeproxy
WORKDIR /app
COPY --from=build /out/edgeproxy /usr/local/bin/edgeproxy
# Containers run as a non-root user, so the bundled container configuration
# listens on 8080 rather than privileged port 80.
COPY configs/compose.json /app/config.json
USER edgeproxy
EXPOSE 8080 9090
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:9090/healthz || exit 1
ENTRYPOINT ["edgeproxy", "-config", "/app/config.json"]
