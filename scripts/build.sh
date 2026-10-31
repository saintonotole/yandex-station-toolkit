#!/usr/bin/env bash
# Local dev build: format, vet, test, then cross-build the Windows exe.
# Requires Go in PATH (see go.mod for the required version).
set -euo pipefail

cd "$(dirname "$0")/.."

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }

required=(
  payloads/dropbearmulti
  payloads/yandex-noupdate.sh
  payloads/yse
)
for file in "${required[@]}"; do
  test -s "$file" || { echo "missing payload: $file (restore it under payloads/)" >&2; exit 1; }
done
test "$(head -c4 payloads/dropbearmulti)" = $'\x7fELF' || {
  echo "payloads/dropbearmulti is not an ELF executable (run scripts/build-dropbear.sh)" >&2
  exit 1
}

echo "== gofmt =="
UNFMT="$(gofmt -l .)"
if [ -n "$UNFMT" ]; then
  gofmt -w .
  echo "reformatted: $UNFMT"
else
  echo "ok"
fi

echo "== go vet =="
go vet ./...

echo "== go test =="
go test ./...

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"
mkdir -p dist

echo "== windows resources ($VERSION) =="
test -s assets/windows/icon.ico || {
  echo "missing assets/windows/icon.ico (it is a committed asset)" >&2
  exit 1
}
go run -mod=mod scripts/make_syso.go \
  -ico assets/windows/icon.ico -manifest assets/windows/app.manifest \
  -o resource_windows_amd64.syso

echo "== build windows/amd64 ($VERSION) =="
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -tags production \
  -ldflags "-s -w -H windowsgui -X main.version=${VERSION}" \
  -o "dist/Yandex Station ToolKit.exe" .

ls -la dist/
echo "done: dist/Yandex Station ToolKit.exe"
