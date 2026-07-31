FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/edgeproxy ./cmd/edgeproxy

FROM alpine:3.20
RUN addgroup -S edgeproxy && adduser -S -G edgeproxy edgeproxy
WORKDIR /app
COPY --from=build /out/edgeproxy /usr/local/bin/edgeproxy
COPY configs/edgeproxy.json /app/config.json
USER edgeproxy
EXPOSE 8080 9090
ENTRYPOINT ["edgeproxy", "-config", "/app/config.json"]
