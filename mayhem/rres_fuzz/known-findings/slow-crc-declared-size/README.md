# CPU/memory exhaustion from a declared chunk size (src/rres.h)

## Reproducer
`slow.rres` (48 bytes): valid `rres` v100 header and one `RAWD` chunk-info record that declares
`packedSize = 0x7FFFFFF0` (just under 2 GB) and `nextOffset = 0`. The file carries no chunk data.

Replay: `/mayhem/rres_fuzz -timeout=5 slow.rres` ends in a libFuzzer timeout (the Mayhemfile
sets `timeout: 5`). Without a limit, the input does finish, after about 210 s in this sanitizer
build.

## Cause
The loaders size the chunk buffer from the untrusted header field and never compare it with
the bytes actually left in the file:

```c
void *data = RRES_CALLOC(info.packedSize, 1);   // ~2 GB, zero-filled
fread(data, info.packedSize, 1, rresFile);      // reads the few bytes that exist
chunk.data = rresLoadResourceChunkData(info, data);
// -> rresComputeCRC32((const unsigned char *)data, info.packedSize) walks all ~2 GB
```

`rresLoadResourceChunk()` and `rresLoadResourceMulti()` each do this for the requested chunk,
and `rresLoadCentralDirectory()` does it for a CDIR chunk. This input therefore costs the
harness two CRC passes over ~2 GB, about 105 s each at -O0 with ASan and UBSan. A declared size
of 2 GB or more exceeds libFuzzer's malloc limit and is reported instead as an excessive
allocation (the "Memory Allocation with Excessive Size Value" defects), which has the same root
cause.

## Impact
Denial of service: a 48-byte file costs a 2 GB allocation plus a CRC pass over it per loader
call. The harness does not guard it, because the input finishes; Mayhem's per-exec `timeout:`
bounds it.

## One-line fix
Before allocating, reject a chunk whose `packedSize` exceeds the bytes left in the file.
