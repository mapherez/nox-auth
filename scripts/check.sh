#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
formatted=$(gofmt -l cmd internal client)
if [ -n "$formatted" ]; then
    printf '%s\n' "$formatted"
    exit 1
fi
go mod tidy -diff
go mod verify
go vet -mod=readonly ./...
go test -race -mod=readonly -count=1 ./...
node --test scripts/release.test.mjs
mkdir -p bin
go build -mod=readonly -trimpath -o bin/nox-auth ./cmd/nox-auth
python3 scripts/smoke.py --binary bin/nox-auth
