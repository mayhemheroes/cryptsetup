#!/usr/bin/env bash
#
# cryptsetup/mayhem/build.sh — build cryptsetup's two OSS-Fuzz LUKS-header harnesses as sanitized
# libFuzzer targets (+ standalone reproducers), and a small self-contained golden oracle program
# (crypt_load over known-good / corrupted LUKS headers) consumed by mayhem/test.sh.
#
# Fuzzed surface = libcryptsetup's on-disk header parser, driven via crypt_load():
#   crypt2_load_fuzz        — LUKS2: harness recomputes the sha256 header checksum over the input
#                             then crypt_load(CRYPT_LUKS2). Exercises the LUKS2 binary header +
#                             JSON metadata parser (json-c).
#   crypt2_load_ondisk_fuzz — writes the raw input and tries crypt_load(LUKS1), then FVAULT2, then
#                             BITLK. Exercises the LUKS1 phdr parser + FileVault2/BitLocker parsers.
# The harness writes the fuzz input into a 16 MiB temp file before crypt_load (see FILESIZE).
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN. We compile cryptsetup ITSELF (libcryptsetup/libcrypto_backend/libutils_io)
# with $SANITIZER_FLAGS so the FUZZED parser code is instrumented. Heavy dependencies that are NOT
# the fuzz target (openssl/devmapper/json-c/blkid/uuid/popt) come from Debian -dev packages — they
# satisfy cryptsetup's configure floor and keep the build small; the upstream oss-fuzz-build.sh
# instead rebuilds all of them statically from git, which is unnecessary for our model.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

OUT="${OUT:-/mayhem}"

# The fuzzers must be built with the sanitizer + libFuzzer coverage instrumentation. Upstream's
# Makefile.am appends -fsanitize=fuzzer-no-link + the sanitizer via CFLAGS/CXXFLAGS, and
# -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION disables hardening that would reject malformed headers.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link"
export CFLAGS="$FUZZ_CFLAGS"
export CXXFLAGS="$FUZZ_CFLAGS"

# ── 1) autotools configure (openssl crypto backend, static, fuzz targets enabled) ─────────────────
./autogen.sh
./configure \
  --enable-static --disable-shared \
  --disable-asciidoc --disable-ssh-token --disable-udev --disable-selinux \
  --with-crypto_backend=openssl \
  --enable-fuzz-targets

# The fuzz-targets make rule has a hard dependency on a static_lib_deps tree (the upstream
# from-source deps). We use system -dev libs instead, so stub the directory to satisfy the guard.
mkdir -p tests/fuzz/build/static_lib_deps/lib

make clean >/dev/null 2>&1 || true
# This builds the instrumented libcryptsetup/libcrypto_backend/libutils_io convenience libs AND
# links the two libFuzzer fuzz binaries under tests/fuzz/.
make -j"$MAYHEM_JOBS" fuzz-targets

# System libs cryptsetup links against (from pkg-config) — needed to relink the standalone form.
SYSLIBS="$(pkg-config --libs libcrypto devmapper json-c blkid uuid popt 2>/dev/null) -lpthread"
# Instrumented static archives produced by the build.
ARCHIVES=".libs/libcryptsetup.a .libs/libcrypto_backend.a .libs/libutils_io.a"

# ── 2) install each libFuzzer target -> $OUT, and relink a standalone reproducer ──────────────────
# Compile the standalone run-once main once (no libFuzzer runtime; feeds files to LLVMFuzzerTestOneInput).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o tests/fuzz/standalone_main.o

for fuzzer in crypt2_load_fuzz crypt2_load_ondisk_fuzz; do
  cp "tests/fuzz/$fuzzer" "$OUT/$fuzzer"

  # standalone reproducer: same harness object, StandaloneFuzzTargetMain instead of -fsanitize=fuzzer.
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
      "tests/fuzz/${fuzzer}-${fuzzer}.o" tests/fuzz/standalone_main.o \
      $ARCHIVES $SYSLIBS \
      -o "$OUT/$fuzzer-standalone"

  echo "built $fuzzer (+ standalone)"
done

# ── 3) golden oracle program for mayhem/test.sh (self-contained crypt_load check) ─────────────────
# Links the instrumented libs and (a) crypt_format()s real LUKS1 + LUKS2 headers onto plain 16 MiB
# files (no device-mapper / no root device required) then crypt_load()s them expecting success, and
# (b) crypt_load()s a header with a corrupted magic expecting failure. test.sh runs this and turns
# the verdicts into CTRF.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC/lib" -I"$SRC" \
    "$SRC/mayhem/crypt_load_oracle.c" $ARCHIVES $SYSLIBS \
    -o "$OUT/crypt_load_oracle"
echo "built crypt_load_oracle"

echo "build.sh complete:"
ls -la "$OUT/crypt2_load_fuzz" "$OUT/crypt2_load_ondisk_fuzz" \
       "$OUT/crypt2_load_fuzz-standalone" "$OUT/crypt2_load_ondisk_fuzz-standalone" \
       "$OUT/crypt_load_oracle" 2>&1 || true
