#!/bin/sh
# wolfSSL for the host build, from the same source tree pspkit-https builds
# the console's from (its wolfssl/ submodule, mounted at /pspkit-https), so
# the desk verifies a chain the way the PSP does.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${TS_WORK:-$HERE/../work}"
OUT="$WORK/wolfssl-host"
SRC="${WOLFSSL_SRC:-/pspkit-https/wolfssl}"
[ -f "$OUT/lib/libwolfssl.a" ] && exit 0
[ -f "$SRC/configure.ac" ] || { echo "no wolfSSL source in $SRC" >&2; exit 1; }

mkdir -p "$WORK"
rm -rf "$WORK/wolfssl-src"
cp -a "$SRC" "$WORK/wolfssl-src"
cd "$WORK/wolfssl-src"
./autogen.sh >"$WORK/wolfssl-host.log" 2>&1
./configure --prefix="$OUT" --enable-static --disable-shared --enable-tls13 \
	--enable-curve25519 --enable-ed25519 --enable-chacha --enable-poly1305 --enable-sni \
	--enable-opensslextra --disable-examples --disable-crypttests \
	CFLAGS="-DWOLFSSL_ALT_CERT_CHAINS -DWOLFSSL_ASN_ALLOW_0_SERIAL -DSP_INT_BITS=4096" >>"$WORK/wolfssl-host.log" 2>&1
make -j"$(nproc)" >>"$WORK/wolfssl-host.log" 2>&1
make install >>"$WORK/wolfssl-host.log" 2>&1
echo "wolfssl for the host in $OUT"
