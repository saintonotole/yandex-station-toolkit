#!/usr/bin/env bash
# Build the universal (amd64+arm64) macOS binary and wrap it in a proper
# .app bundle with an Info.plist. This is required for macOS Local Network
# privacy: per Apple's TN3179 "Understanding local network privacy", a bare
# executable that presents a GUI is not a command-line tool and is not
# auto-exempted, so the system needs a bundle (and usage description) to
# attribute and prompt for the Local Network permission. Without it, the
# app's scans fail silently with no permission prompt.
# https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy
set -euo pipefail

cd "$(dirname "$0")/.."

command -v go >/dev/null || { echo "go not found in PATH" >&2; exit 1; }
command -v lipo >/dev/null || { echo "lipo not found (requires macOS/Xcode CLT)" >&2; exit 1; }

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
APP_NAME="Yandex Station ToolKit"
OUT_APP="dist/${APP_NAME}.app"
ICON="assets/darwin/AppIcon.icns"

test -s "$ICON" || { echo "missing $ICON (committed asset — restore it from git)" >&2; exit 1; }

rm -rf "$OUT_APP"
mkdir -p "$OUT_APP/Contents/MacOS" "$OUT_APP/Contents/Resources"
cp "$ICON" "$OUT_APP/Contents/Resources/AppIcon.icns"

echo "== build darwin universal ($VERSION) =="
for arch in amd64 arm64; do
  CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" \
    CGO_LDFLAGS="-framework UniformTypeIdentifiers" \
    go build -trimpath -tags production \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "dist/.${APP_NAME}-darwin-${arch}" .
done
lipo -create -output "$OUT_APP/Contents/MacOS/${APP_NAME}" \
  "dist/.${APP_NAME}-darwin-amd64" "dist/.${APP_NAME}-darwin-arm64"
rm "dist/.${APP_NAME}-darwin-amd64" "dist/.${APP_NAME}-darwin-arm64"
chmod +x "$OUT_APP/Contents/MacOS/${APP_NAME}"

sed "s/{{VERSION}}/${VERSION}/g" assets/darwin/Info.plist.template \
  > "$OUT_APP/Contents/Info.plist"

# Ad hoc signing (no Apple Developer ID available here). Per TN3179, local
# network privacy identity tracking is only reliable with an Apple-issued
# signing identity, but ad hoc signing still gives the bundle a stable
# identity for a single build, which is enough for the permission prompt to
# work and persist across runs of that build.
if command -v codesign >/dev/null; then
  codesign --force --deep --sign - "$OUT_APP"
fi

echo "done: $OUT_APP"
