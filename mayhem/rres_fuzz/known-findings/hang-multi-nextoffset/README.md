# Infinite loop (hang) in rresLoadResourceMulti (src/rres.h)

## Reproducer
`hang.rres` (59 bytes): valid `rres` v100 header, one well-formed `RAWD` chunk (CRC32 OK)
whose `nextOffset = 0xFFFFFFF0` points past end-of-file.

The fuzz harness no longer lets this loop run. Before calling `rresLoadResourceMulti()`, it
follows the same links itself and rejects an input whose chain never ends
(`multi_walk_ends()` in `mayhem/harnesses/rres_fuzz.c`): a link at or past EOF is rejected at
once, and any other chain is rejected once it is still going after one link per input byte. So
`/mayhem/rres_fuzz-standalone hang.rres` returns at once. To reproduce the hang, call the loader
directly (inside the image):

    printf '#define RRES_IMPLEMENTATION\n#include "rres.h"\nint main(int c, char **v) { (void)c; rresUnloadResourceMulti(rresLoadResourceMulti(v[1], 0x8b387909)); return 0; }\n' > /tmp/multi.c
    clang -I/mayhem/src /tmp/multi.c -o /tmp/multi
    timeout 10 /tmp/multi hang.rres; echo $?    # 124: still looping after 10 s

`0x8b387909` is the id of the file's first chunk, which is the id the harness requests.

## Cause
The linked-chunk walk in `rresLoadResourceMulti()` trusts `nextOffset` and never checks
that the `fread` succeeded:

```c
while (temp.nextOffset != 0) {
    fseek(rresFile, temp.nextOffset, SEEK_SET);          // seek past EOF: succeeds
    fread(&temp, sizeof(rresResourceChunkInfo), 1, rresFile);  // fails at EOF: temp UNCHANGED
    rres.count++;                                        // temp.nextOffset still != 0 -> loop
}
```

When `fseek` lands at/after EOF, `fread` reads nothing and leaves `temp` (hence
`temp.nextOffset`) unchanged, so the loop never terminates. `rres.count` just wraps around, and
the allocation after the loop is never reached. Links that form a cycle (a chunk whose
`nextOffset` leads back to an earlier one) loop forever in the same way. The load loop that
follows walks the same links with the same unchecked `fread`.

## Impact
Denial of service: a single crafted `.rres` file makes `rresLoadResourceMulti()` spin forever.
It is very shallow, since any non-zero `nextOffset` outside the file on the requested chunk
triggers it, so an unguarded fuzzer keeps getting stuck on it. Mayhem's stored corpus also holds
an input that reaches it (`a213fd8d…`, 37 bytes, whose truncated first record gives
`nextOffset = 0x4a`) whenever the memory limit admits that input's 2.5 GB chunk allocation.
Under libFuzzer's default 2048 MB limit, that input stops earlier, as an out-of-memory error in
`rresLoadResourceChunk`. The harness therefore guards the hang with the deterministic link budget
above instead of a watchdog timer (#1298).

## One-line fix
In the `nextOffset` walk, check the `fread` return value and stop on a short read, and require
`nextOffset` to stay in-bounds and strictly increase (or cap the walk at `header.chunkCount`
links) so that a cycle cannot loop either.
