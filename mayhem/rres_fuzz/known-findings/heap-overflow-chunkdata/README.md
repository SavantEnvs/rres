# heap-buffer-overflow in rresLoadResourceChunkData (src/rres.h)

## Reproducer
`crash.rres` (48 bytes): valid `rres` v100 header, one `RAWD` chunk with
`packedSize = 0`, `baseSize = 0`, `crc32 = 0`.

Replay: `/mayhem/rres_fuzz-standalone crash.rres`

## Cause
`rresLoadResourceChunk()` allocates the chunk buffer with the attacker-controlled
`info.packedSize`:

```c
void *data = RRES_CALLOC(info.packedSize, 1);   // packedSize == 0 -> 0/1-byte region
fread(data, info.packedSize, 1, rresFile);
chunk.data = rresLoadResourceChunkData(info, data);
```

`rresLoadResourceChunkData()` then reads 4 bytes unconditionally once the CRC32 gate
passes (CRC32 of 0 bytes is 0, which matches `crc32 = 0`):

```c
chunkData.propCount = ((unsigned int *)data)[0];   // src/rres.h:1073 — 4-byte OOB read
```

With `packedSize < 4` the read runs past the 0/1-byte allocation → heap-buffer-overflow.
The subsequent `rawSize = info.baseSize - sizeof(int) - propCount*sizeof(int)` is also
attacker-controlled and can go negative, feeding a huge unsigned `memcpy`.

## Impact
Out-of-bounds read (info leak / crash) from a crafted `.rres` file; no bounds check ties
`packedSize`/`baseSize` to the amount of data actually needed before dereferencing it.

## One-line fix
In `rresLoadResourceChunkData`, require `info.packedSize >= sizeof(unsigned int)` (and
validate `baseSize >= sizeof(int) + propCount*sizeof(int)`) before reading `props`/`raw`.
