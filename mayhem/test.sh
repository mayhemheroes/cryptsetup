#!/usr/bin/env bash
#
# cryptsetup/mayhem/test.sh — RUN the self-contained crypt_load golden oracle built by
# mayhem/build.sh and emit a CTRF summary. exit 0 iff every oracle check passed.
#
# ORACLE SOURCE: mayhem/crypt_load_oracle.c — exercises the exact crypt_load() header-parser path
# the fuzz harnesses hit. For LUKS1 and LUKS2 it crypt_format()s a real header onto a plain 16 MiB
# file (no device-mapper / no root — the same way the harnesses operate) and asserts:
#   * a freshly formatted header LOADS  (rc == 0)        — positive / parse-correctness check
#   * a header with smashed magic FAILS (rc != 0)        — negative check; an "always return 0" or
#                                                          no-op patch to the loader cannot pass it
# 4 checks total (luks1+luks2 x positive+negative). This RUNS the pre-built binary; never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

OUT="${OUT:-/mayhem}"
ORACLE="$OUT/crypt_load_oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-$PWD}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "crypt_load_oracle" 0 1 0; exit 2
fi

echo "=== running crypt_load golden oracle ==="
# Leaks in the one-shot oracle process are not the signal we care about here.
out="$(ASAN_OPTIONS=detect_leaks=0 "$ORACLE" 2>&1)"; rc=$?
echo "$out"

PASSED=$(printf '%s\n' "$out" | grep -c '^PASS ')
FAILED=$(printf '%s\n' "$out" | grep -c '^FAIL ')
: "${PASSED:=0}" "${FAILED:=0}"

# If we parsed no PASS/FAIL lines, fall back to the process exit code.
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "could not parse oracle output; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "crypt_load_oracle" 1 0 0; exit 0; }
  emit_ctrf "crypt_load_oracle" 0 1 0; exit 1
fi

# A nonzero process exit with no parsed FAIL (e.g. a sanitizer abort) is still a failure.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  FAILED=1
fi

emit_ctrf "crypt_load_oracle" "$PASSED" "$FAILED" 0
