FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/securityedge ./cmd/securityedge

FROM alpine:3.21
RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=build /out/securityedge /usr/local/bin/securityedge
COPY configs /app/configs
COPY integration /app/integration
USER app
EXPOSE 8081 9191
ENTRYPOINT ["securityedge"]
CMD ["-config", "/app/configs/local-dev.json"]
