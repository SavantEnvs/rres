#!/usr/bin/env bash
#
# mayhem/build.sh — build the rres (.rres) parser fuzz harness + standalone reproducer +
# the known-answer oracle probe, plus the build-time LSan off-switch (mayhem/lsan_off.cc).
# rres is a single-header library (src/rres.h): the harness
# defines RRES_IMPLEMENTATION, so the library and harness are ONE translation unit — the
# fuzzer/standalone compiles therefore instrument the whole parser (no separate lib to link).
#
# Runs inside the commit image as `mayhem` in /mayhem. Build-contract env from the base:
#   CC / CXX / LIB_FUZZING_ENGINE / SANITIZER_FLAGS / STANDALONE_FUZZ_MAIN / SRC.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DWARF < 4: the base's SANITIZER_FLAGS end in a plain -g (DWARF-5). $DEBUG_FLAGS must come
# AFTER $SANITIZER_FLAGS on every fuzz/standalone compile+link so its -gdwarf-3 wins.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN

cd "$SRC"

INC="-I$SRC/src"
HARNESS="$SRC/mayhem/harnesses/rres_fuzz.c"
PROBE="$SRC/mayhem/harnesses/rres_probe.c"
# Silence the library's printf logging in the fuzz/standalone builds (fast + quiet fuzzing).
QUIET="-DRRES_SUPPORT_LOG_INFO=0"

echo ">> [0/3] LeakSanitizer build-time off-switch (mayhem/lsan_off.cc — fleet policy, PORTING.md)"
# Compiled with $SANITIZER_FLAGS and linked into EVERY fuzz + -standalone binary: leaks are not the
# bug class this fleet fuzzes for, and this weak-interface hook is the only sanctioned way to drop
# just leak detection (never a runtime __lsan_disable() wrap, never a compiled-in options override).
LSAN_OFF=/tmp/lsan_off.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_OFF"

echo ">> [1/3] fuzzer (ASan+UBSan + SanCov via -fsanitize=fuzzer-no-link, whole parser instrumented)"
# -fsanitize=fuzzer-no-link is added UNCONDITIONALLY (even if $SANITIZER_FLAGS is empty) so the
# fuzzed code carries SanCov edge instrumentation — without it Mayhem records 0 edges.
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS $QUIET $INC \
    "$HARNESS" "$LSAN_OFF" $LIB_FUZZING_ENGINE -o /mayhem/rres_fuzz
[ -x /mayhem/rres_fuzz ]

echo ">> [2/3] standalone run-once reproducer (STANDALONE_FUZZ_MAIN, no libFuzzer runtime)"
# The standalone driver is a C file; compile it to an object with -x c, then link the harness.
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -c -x c \
    "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS $QUIET $INC \
    "$HARNESS" /tmp/standalone_main.o "$LSAN_OFF" -o /mayhem/rres_fuzz-standalone
[ -x /mayhem/rres_fuzz-standalone ]

echo ">> [3/3] KAT oracle probe (NORMAL flags: no sanitizer, no -gdwarf-3 — honest oracle)"
$CC -O2 $INC "$PROBE" -o /mayhem/rres_probe
[ -x /mayhem/rres_probe ]

echo ">> build.sh OK"
ls -l /mayhem/rres_fuzz /mayhem/rres_fuzz-standalone /mayhem/rres_probe
