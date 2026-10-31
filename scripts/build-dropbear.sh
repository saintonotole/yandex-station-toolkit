#!/usr/bin/env bash
# Rebuild payloads/dropbearmulti from the signed upstream release. Requires Docker.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-2026.94}"
SHA256="${DROPBEAR_SHA256:-e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81}"
KEY_FPR="F7347EF2EE2E07A267628CA944931494F29C6773"
BASE="https://matt.ucc.asn.au/dropbear/releases"
ZLIB_VERSION="${ZLIB_VERSION:-1.3.2}"
ZLIB_SHA256="${ZLIB_SHA256:-bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16}"

work=".tmp/dropbear"
mkdir -p "$work"
for f in "dropbear-$VERSION.tar.bz2" "dropbear-$VERSION.tar.bz2.asc" dropbear-key-2015.asc; do
  [ -s "$work/$f" ] || curl -fsSL -o "$work/$f" "$BASE/$f"
done
[ -s "$work/zlib-$ZLIB_VERSION.tar.gz" ] || curl -fsSL -o "$work/zlib-$ZLIB_VERSION.tar.gz" \
  "https://zlib.net/zlib-$ZLIB_VERSION.tar.gz"
echo "$SHA256  $work/dropbear-$VERSION.tar.bz2" | shasum -a 256 -c -
echo "$ZLIB_SHA256  $work/zlib-$ZLIB_VERSION.tar.gz" | shasum -a 256 -c -

docker run --rm -v "$PWD":/w -w /w \
  -e VERSION="$VERSION" -e KEY_FPR="$KEY_FPR" -e ZLIB_VERSION="$ZLIB_VERSION" \
  alpine:3.22 sh -euc '
apk add -q --no-cache gnupg zig make bzip2 file >/dev/null
cd .tmp/dropbear
export GNUPGHOME="$(mktemp -d)"
gpg -q --import dropbear-key-2015.asc
gpg -q --status-fd 1 --verify "dropbear-$VERSION.tar.bz2.asc" "dropbear-$VERSION.tar.bz2" \
  | grep -q "VALIDSIG $KEY_FPR" || { echo "bad signature" >&2; exit 1; }

# Build inside the container: the bind-mounted host tree may be
# case-insensitive (macOS), which breaks the libtommath makefile.
src="$(mktemp -d)"
tar -xjf "dropbear-$VERSION.tar.bz2" -C "$src"
cd "$src/dropbear-$VERSION"

# Station layout: rootfs is read-only, everything lives under /data/opt.
cat > localoptions.h <<"EOF"
#define DSS_PRIV_FILENAME "/data/opt/etc/dropbear/dropbear_dss_host_key"
#define RSA_PRIV_FILENAME "/data/opt/etc/dropbear/dropbear_rsa_host_key"
#define ECDSA_PRIV_FILENAME "/data/opt/etc/dropbear/dropbear_ecdsa_host_key"
#define ED25519_PRIV_FILENAME "/data/opt/etc/dropbear/hk_ed25519"
#define SFTPSERVER_PATH "/data/opt/libexec/sftp-server"
#define DEFAULT_PATH "/data/opt/bin:/opt/bin:/usr/bin:/bin"
#define DEFAULT_ROOT_PATH "/data/opt/sbin:/data/opt/bin:/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#define DROPBEAR_X11FWD 0
EOF

export CC="zig cc -target arm-linux-musleabihf -mcpu=generic+v7a+vfp3+neon"
export AR="zig ar" RANLIB="zig ranlib"

zlib_src="$(mktemp -d)"
tar -xzf "/w/.tmp/dropbear/zlib-$ZLIB_VERSION.tar.gz" -C "$zlib_src"
(
  cd "$zlib_src/zlib-$ZLIB_VERSION"
  CFLAGS="-Os" ./configure --static --prefix="$zlib_src/install"
  make -j"$(nproc)" libz.a
  make install
)

./configure --host=arm-linux-musleabihf --enable-static \
  --with-zlib="$zlib_src/install" \
  --disable-syslog --disable-lastlog --disable-utmp --disable-utmpx \
  --disable-wtmp --disable-wtmpx --disable-pututline --disable-pututxline \
  CFLAGS="-Os -ffunction-sections -fdata-sections" \
  LDFLAGS="-Wl,--gc-sections -Wl,-s" LTM_CFLAGS=-Os >/dev/null
make -j"$(nproc)" PROGRAMS="dropbear dropbearkey" MULTI=1 >/dev/null
file dropbearmulti
cp dropbearmulti /w/payloads/dropbearmulti
'

ls -la payloads/dropbearmulti
