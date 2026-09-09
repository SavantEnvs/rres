#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral oracle for the rres parser. RUNS the KAT probe that
# mayhem/build.sh compiled (/mayhem/rres_probe) against a fixed committed seed and asserts
# EXACT parsed values via grep. If the program is neutered to exit(0) (the sabotage shim),
# the probe prints nothing, every assertion misses, and this script FAILS — which is the
# behavioral property the gate requires. Emits a CTRF summary. Does NOT compile anything.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
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

PROBE=/mayhem/rres_probe
SEED="$SRC/mayhem/rres_fuzz/testsuite/seed_cdir.rres"

# Unconditional: a missing binary or fixture is a FAILURE, never a skip.
if [ ! -x "$PROBE" ]; then echo "FATAL: $PROBE missing (build.sh bug)" >&2; emit_ctrf "rres-kat" 0 1; exit 1; fi
if [ ! -f "$SEED" ];  then echo "FATAL: $SEED missing" >&2;               emit_ctrf "rres-kat" 0 1; exit 1; fi

OUT="$("$PROBE" "$SEED" 2>/dev/null || true)"
echo "---- probe output ----"; echo "$OUT"; echo "----------------------"

passed=0; failed=0
check() {  # check <label> <exact-expected-line>
  if printf '%s\n' "$OUT" | grep -qxF "$2"; then
    echo "PASS: $1 ($2)"; passed=$((passed+1))
  else
    echo "FAIL: $1 (expected '$2')"; failed=$((failed+1))
  fi
}

# Known-answer values for seed_cdir.rres (2 chunks: RAWD + CDIR; 1 CDIR entry -> data.txt).
check "chunk count"          "COUNT=2"
check "chunk0 FourCC"        "FOURCC0=RAWD"
check "chunk1 FourCC"        "FOURCC1=CDIR"
check "RAWD data type"       "DATATYPE0=1"
check "RAWD prop count"      "PROPCOUNT=1"
check "RAWD prop[0] size"    "PROP0=3"
check "RAWD raw bytes"       "RAW=abc"
check "central dir count"    "CDCOUNT=1"
check "central dir filename" "CDNAME=data.txt"

emit_ctrf "rres-kat" "$passed" "$failed"
