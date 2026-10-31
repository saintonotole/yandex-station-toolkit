#!/usr/bin/env bash
# Package the Linux build as a self-contained directory + tarball.
#
# The app is a webview GUI: on Linux it renders through WebKitGTK, which on
# most machines is not installed (and on immutable distros like Bazzite
# cannot be installed). This script collects the library closure of the
# binary into lib/, copies the WebKit helper processes next to it, and
# binary-patches the compiled-in absolute helper path
# (/usr/lib/<triple>/webkit2gtk-4.1) to a writable per-arch staging dir
# (/var/tmp/.ystk/<arch>/webkit2gtk-4.1) that run.sh populates at launch,
# because WebKitGTK resolves helpers only through that absolute path and
# offers no environment override. WebKit's own bwrap sandbox is disabled in
# run.sh: the helpers must run from the staging dir, which the sandbox
# would hide.
#
# Dependencies are resolved with readelf, not ldd, so the script works for
# cross-compiled binaries (ldd cannot execute foreign-arch ELF images).
#
# Result: ./Yandex Station ToolKit-linux-amd64|arm64/ (bin/, lib/, run.sh)
#         and ./Yandex Station ToolKit-linux-amd64|arm64.tar.zst
#
# Usage: scripts/package-linux-libs.sh [version]
# Env:   BIN  - path to the built binary (default: build/yandex-station-toolkit)
#        OUT  - output directory (default: dist)
set -euo pipefail

VERSION="${1:-dev}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$REPO/build/yandex-station-toolkit}"
OUT="${OUT:-$REPO/dist}"

[ -x "$BIN" ] || { echo "binary not found: $BIN (build it first)" >&2; exit 1; }
for tool in readelf python3 tar zstd find; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

# Architecture from the ELF header: multiarch triple + short arch tag.
ELF_MACHINE=$(readelf -h "$BIN" | sed -n 's/^ *Machine: *//p')
case "$ELF_MACHINE" in
    "Advanced Micro Devices X86-64")
        TRIPLE=x86_64-linux-gnu; ARCHTAG=amd64 ;;
    AArch64)
        TRIPLE=aarch64-linux-gnu; ARCHTAG=arm64 ;;
    *)
        echo "unsupported ELF machine: $ELF_MACHINE" >&2; exit 1 ;;
esac
OLDPATH="/usr/lib/$TRIPLE/webkit2gtk-4.1"
NEWPATH="/var/tmp/.ystk/$ARCHTAG/webkit2gtk-4.1"
# Cross builds keep the arm64 libraries in a sysroot instead of the host's
# multiarch dirs; both the dependency lookup and the helper source shift.
EXTRA_LIBDIR="${EXTRA_LIBDIR:-}"
HELPERS_SRC="${HELPERS_SRC:-$OLDPATH}"

PKG="$OUT/Yandex Station ToolKit-linux-$ARCHTAG"
case "$BIN" in "$PKG"|"$PKG"/*)
    echo "BIN must live outside the package dir ($PKG)" >&2; exit 1 ;;
esac

rm -rf "$PKG"
mkdir -p "$PKG/bin" "$PKG/lib"

cp "$BIN" "$PKG/bin/yandex-station-toolkit"
chmod 755 "$PKG/bin/yandex-station-toolkit"

# --- collect the library closure -------------------------------------------
# The glibc core stays on the host: the bundled libraries come from this
# build machine, so the host needs a glibc at least as new (Ubuntu 24.04
# era, 2.39). Dependencies are looked up by soname in the multiarch dirs,
# which works for both native and cross builds.
CORE='^(ld-linux-x86-64\.so\.2|ld-linux-aarch64\.so\.1|libc\.so\.6|libm\.so\.6|libdl\.so\.2|libpthread\.so\.0|librt\.so\.1|libresolv\.so\.2)$'

needed_of() { # print the DT_NEEDED sonames of $1
    readelf -d "$1" 2>/dev/null |
        sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p'
}

resolve() { # print the host path of $1 (a soname), empty if absent
    for dir in "$PKG/lib" "$EXTRA_LIBDIR" "/usr/lib/$TRIPLE" "/lib/$TRIPLE"; do
        if [ -n "$dir" ] && [ -e "$dir/$1" ]; then printf '%s' "$dir/$1"; return; fi
    done
}

seed() { # copy every non-core dependency of $1 into PKG/lib
    local soname found
    while IFS= read -r soname; do
        if [ -z "$soname" ]; then continue; fi
        if echo "$soname" | grep -qE "$CORE"; then continue; fi
        if [ -e "$PKG/lib/$soname" ]; then continue; fi
        found=$(resolve "$soname")
        if [ -z "$found" ]; then
            echo "unresolved dependency: $soname (needed by $1)" >&2
            exit 1
        fi
        cp -L "$found" "$PKG/lib/$soname"
    done < <(needed_of "$1")
}

seed "$PKG/bin/yandex-station-toolkit"

# WebKit helper processes + injected bundle keep their relative layout
# (libdir/webkit2gtk-4.1); they are patched below like every other library.
if [ -d "$HELPERS_SRC" ]; then
    mkdir -p "$PKG/lib/webkit2gtk-4.1"
    cp -a "$HELPERS_SRC/." "$PKG/lib/webkit2gtk-4.1/"
    for h in "$PKG/lib/webkit2gtk-4.1/"WebKit*; do
        if [ -f "$h" ]; then seed "$h"; fi
    done
fi

for _ in 1 2 3 4 5 6 7 8; do
    before=$(find "$PKG/lib" -type f | wc -l)
    while IFS= read -r f; do seed "$f"; done < <(find "$PKG/lib" -type f)
    if [ "$(find "$PKG/lib" -type f | wc -l)" = "$before" ]; then break; fi
done

# --- repoint the compiled-in helper path ------------------------------------
# Every bundled file (and the binary itself) that embeds OLDPATH gets it
# rewritten to NEWPATH. The replacement is shorter, so each rewritten string
# is NUL-padded to its original length; string tails that follow the prefix
# (e.g. "/injected-bundle/") are preserved.
python3 - "$PKG" "$OLDPATH" "$NEWPATH" <<'EOF'
import os, sys
pkg, old, new = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
assert len(new) <= len(old), "replacement path must not be longer"
for root, _, files in os.walk(pkg):
    for name in files:
        path = os.path.join(root, name)
        with open(path, 'rb') as fh:
            data = bytearray(fh.read())
        i, n = -1, 0
        while True:
            i = data.find(old, i + 1)
            if i < 0:
                break
            j = data.find(b'\0', i + len(old))       # end of the full string
            tail = bytes(data[i + len(old):j])       # '' or '/injected-bundle/'
            replacement = new + tail
            span = len(old) + len(tail)
            data[i:i + span] = replacement + b'\0' * (span - len(replacement))
            n += 1
        if n:
            with open(path, 'wb') as fh:
                fh.write(data)
            print(f"patched {n:2d} path(s) in {os.path.relpath(path, pkg)}")
EOF

# --- completeness check ------------------------------------------------------
# Every DT_NEEDED of every bundled file must resolve inside the package or be
# glibc-core; anything else means the closure is broken on the target host.
MISSING=0
while IFS= read -r f; do
    while IFS= read -r soname; do
        if echo "$soname" | grep -qE "$CORE"; then continue; fi
        if [ ! -e "$PKG/lib/$soname" ]; then
            echo "incomplete closure: $soname (needed by $f)" >&2
            MISSING=1
        fi
    done < <(needed_of "$f")
done < <(find "$PKG/lib" -type f)
if [ "$MISSING" = 1 ]; then
    echo "library closure incomplete; aborting" >&2
    exit 1
fi

# --- launcher ----------------------------------------------------------------
# Stages the helpers where the patched path expects them and runs the app.
# The stamp guards against a staging dir left by a different package version.
cat > "$PKG/run.sh" <<EOF
#!/bin/sh
# Self-contained launcher: provides the bundled libraries (WebKitGTK and its
# closure) and stages the WebKit helper processes where the patched library
# looks for them. Requires glibc >= 2.39 (Ubuntu 24.04 / Fedora 40 era).
HERE=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
STAGE=$NEWPATH
STAMP="\$STAGE/.pkg-version"
if [ "\$(cat "\$STAMP" 2>/dev/null)" != "$VERSION" ]; then
    mkdir -p "\$STAGE"
    if ! cp -a "\$HERE/lib/webkit2gtk-4.1/." "\$STAGE/"; then
        echo "cannot update \$STAGE (owned by another user?); remove it and retry" >&2
        exit 1
    fi
    echo "$VERSION" > "\$STAMP" 2>/dev/null || true
fi
LD_LIBRARY_PATH="\$HERE/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
# WebKit's bwrap sandbox would hide the staged helpers; this app only ever
# renders its own localhost UI, so the helper sandbox is off.
WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS
exec "\$HERE/bin/yandex-station-toolkit" "\$@"
EOF
chmod 755 "$PKG/run.sh"

# --- archive -----------------------------------------------------------------
tar --zstd -cf "$OUT/Yandex Station ToolKit-linux-$ARCHTAG.tar.zst" \
    -C "$OUT" "Yandex Station ToolKit-linux-$ARCHTAG"
echo "packaged: $PKG and $OUT/Yandex Station ToolKit-linux-$ARCHTAG.tar.zst"
du -sh "$PKG" "$OUT/Yandex Station ToolKit-linux-$ARCHTAG.tar.zst"
