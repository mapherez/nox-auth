# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags "-X main.version=${VERSION}" -o /out/nox-auth ./cmd/nox-auth
FROM alpine:3.23
RUN apk add --no-cache ca-certificates \
 && addgroup -g 10001 noxsuite \
 && adduser -D -H -u 10004 -G noxsuite noxauth \
 && mkdir -p /data /run/nox-suite /run/nox-auth-admin \
 && chown 10004:10001 /data /run/nox-suite /run/nox-auth-admin \
 && chmod 0700 /data \
 && chmod 3770 /run/nox-suite /run/nox-auth-admin
COPY --from=build /out/nox-auth /usr/local/bin/nox-auth
ENV NOX_AUTH_LISTEN_ADDR=0.0.0.0:8080 NOX_AUTH_DATA_DIR=/data NOX_AUTH_SUITE_SOCKET_DIR=/run/nox-suite NOX_AUTH_ADMIN_SOCKET_DIR=/run/nox-auth-admin
USER noxauth
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/nox-auth", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/nox-auth"]
