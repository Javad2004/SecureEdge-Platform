FROM golang:1.23-alpine AS build

ARG VERSION=development
ARG COMMIT=container
ARG BUILD_TIME=unknown

WORKDIR /src

COPY apps/securityedge/go.mod ./
COPY apps/securityedge/ ./

RUN CGO_ENABLED=0 go test ./... \
 && CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w \
    -X github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version.Version=${VERSION} \
    -X github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version.Commit=${COMMIT} \
    -X github.com/Javad2004/SecureEdge-Platform/apps/securityedge/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/securityedge ./cmd/securityedge

FROM alpine:3.21

ARG VERSION=development

LABEL org.opencontainers.image.title="SecurityEdge" \
      org.opencontainers.image.description="Application-layer WAF, traffic protection, and EdgeProxy operations dashboard" \
      org.opencontainers.image.version="${VERSION}"

RUN apk add --no-cache ca-certificates \
 && addgroup -S app \
 && adduser -S -G app app \
 && mkdir -p /app/config /app/configs /app/logs \
 && chown -R app:app /app/config /app/logs

WORKDIR /app

COPY --from=build /out/securityedge /usr/local/bin/securityedge
COPY apps/securityedge/configs /app/configs
COPY --chown=app:app apps/securityedge/configs/compose.json /app/config/securityedge.json
COPY integration /integration

USER app

VOLUME ["/app/config", "/app/logs"]
EXPOSE 8081 9191

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:9191/readyz || exit 1

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/securityedge"]
CMD ["-config", "/app/config/securityedge.json"]
