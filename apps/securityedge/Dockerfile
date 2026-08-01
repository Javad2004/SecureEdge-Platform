FROM golang:1.23-alpine AS build
ARG VERSION=3.1.0-professional-connectivity
ARG COMMIT=container
ARG BUILD_TIME=unknown
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go test ./... \
 && CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/bachelor-project/edgeproxy-security/internal/version.Version=${VERSION} -X github.com/bachelor-project/edgeproxy-security/internal/version.Commit=${COMMIT} -X github.com/bachelor-project/edgeproxy-security/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/securityedge ./cmd/securityedge

FROM alpine:3.21
LABEL org.opencontainers.image.title="SecurityEdge" \
      org.opencontainers.image.description="Application-layer WAF, traffic protection, and EdgeProxy operations dashboard" \
      org.opencontainers.image.version="3.1.0-professional-connectivity"
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=build /out/securityedge /usr/local/bin/securityedge
COPY configs /app/configs
COPY integration /app/integration
RUN mkdir -p /app/logs && chown -R app:app /app/logs
USER app
EXPOSE 8081 9191
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:9191/healthz >/dev/null || exit 1
ENTRYPOINT ["securityedge"]
CMD ["-config", "/app/configs/local-dev.json"]
