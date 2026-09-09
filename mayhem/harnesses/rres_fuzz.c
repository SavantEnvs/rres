// rres_fuzz.c — in-process libFuzzer harness for the rres (.rres) file/chunk parser.
//
// rres is a single-header resource-packaging FORMAT LOADER (src/rres.h). Its public
// loader API takes a FILE PATH (fopen/fread), not an in-memory buffer, so there is no
// in-memory entry point to target directly. We therefore stage the fuzzer-provided bytes
// into a harness-owned scratch file and hand that path to the parser. The scratch file
// follows the fleet convention (PORTING.md, SPEC.md §6.2 item 13): it is created ONCE with
// mkstemp() under $TMPDIR (fallback /tmp — Mayhem's cwd and /tmp are writable; the image
// dir is read-only) and rewritten per input. No hardcoded /tmp or /dev/shm path. Byte-in
// only: besides that scratch file (which it also reads back for the link budget below) the
// harness does no other file I/O and reads no committed path.
//
// Surface exercised (the whole .rres header/chunk parser):
//   - rresLoadResourceChunkInfoAll : header + every chunk-info record + the seek walk
//   - rresLoadResourceChunk        : single-chunk load + rresLoadResourceChunkData
//                                    (propCount/props[] parse, CRC32 gate, raw copy)
//   - rresLoadResourceMulti        : multi/linked-chunk load (nextOffset walk; an input whose
//                                    walk never ends is rejected instead, see multi_walk_ends)
//   - rresLoadCentralDirectory     : CDIR parse (dir entries, fileName copy)
//   - rresGetDataType / rresGetResourceId / rresComputeCRC32
//
// We derive the resource id to request from the file's own first chunk-info record so the
// id-match branch (the deep parse path) is actually reached instead of always missing.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define RRES_IMPLEMENTATION
#include "rres.h"

// Stable per-process scratch path: $TMPDIR/rres_in_XXXXXX, created by mkstemp() in the
// constructor (unique per process, so parallel fork workers never collide) and truncated +
// rewritten for every input. Removed again at exit.
static char g_path[4096];
static int g_path_ok = 0;

static void remove_scratch(void) {
    if (g_path_ok) unlink(g_path);
}

// --- link budget for the one known upstream hang ------------------------------
// rresLoadResourceMulti() (src/rres.h) follows the requested chunk's nextOffset links until
// one is 0 and never checks that fread() succeeded, so a link at or past EOF leaves the record
// unchanged and the loop re-reads it forever; a cycle of links spins the same way
// (mayhem/rres_fuzz/known-findings/hang-multi-nextoffset/). Such an input never returns, and
// that loop only seeks and reads into a stack record, so it has nothing else to report.
// Before calling the loader the harness therefore follows the same links itself (the same
// record search and the same fseek()/fread() calls on the same file) and rejects the input
// if the chain never ends. That test is exact: a link at or past EOF (offset >= size) reads
// nothing, so it repeats forever; any other link's successor depends only on its own offset,
// so a chain that ends visits distinct offsets in [1, size), at most size - 1 links, and a
// budget of `size` links separates the two. Every input the loader can finish still reaches
// it. This counts links, never time.
static int multi_walk_ends(const char *path, unsigned int id, size_t size) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 1;    // the loader's own fopen() fails the same way and it returns
    int ends = 1;
    rresFileHeader header = { 0 };
    (void)fread(&header, sizeof(rresFileHeader), 1, f);
    if ((header.id[0] == 'r') && (header.id[1] == 'r') && (header.id[2] == 'e') &&
        (header.id[3] == 's') && (header.version == 100)) {
        for (int i = 0; i < header.chunkCount; i++) {
            rresResourceChunkInfo info = { 0 };
            (void)fread(&info, sizeof(rresResourceChunkInfo), 1, f);
            if (info.id == id) {
                for (size_t links = 0; info.nextOffset != 0; links++) {
                    if (info.nextOffset >= size || links == size) { ends = 0; break; }
                    fseek(f, info.nextOffset, SEEK_SET);
                    (void)fread(&info, sizeof(rresResourceChunkInfo), 1, f);
                }
                break;
            }
            fseek(f, info.packedSize, SEEK_CUR);
        }
    }
    fclose(f);
    return ends;
}

__attribute__((constructor))
static void init_harness(void) {
    // Harness-owned scratch file: $TMPDIR (fallback /tmp) + mkstemp() — never a hardcoded path.
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || *tmpdir == '\0') tmpdir = "/tmp";
    int n = snprintf(g_path, sizeof(g_path), "%s/rres_in_XXXXXX", tmpdir);
    if (n > 0 && (size_t)n < sizeof(g_path)) {
        int fd = mkstemp(g_path);
        if (fd >= 0) {
            close(fd);
            g_path_ok = 1;
            atexit(remove_scratch);
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Stage the fuzzer bytes to the scratch file the loader can fopen() (truncate + rewrite).
    if (!g_path_ok) return 0;
    FILE *f = fopen(g_path, "wb");
    if (f == NULL) return 0;
    if (size > 0) fwrite(data, 1, size, f);
    fclose(f);

    // Load every chunk-info record (also validates the header + seek walk).
    unsigned int count = 0;
    rresResourceChunkInfo *infos = rresLoadResourceChunkInfoAll(g_path, &count);

    // Pick an id that exists in the file (when any) so the id-match deep path is hit,
    // plus a fixed fallback so the not-found path is exercised on other inputs.
    unsigned int id = 0xCAFEF00D;
    if (infos != NULL && count > 0) id = infos[0].id;
    RRES_FREE(infos);

    // Single-chunk load: exercises rresLoadResourceChunkData (props + CRC32 + raw copy).
    rresResourceChunk chunk = rresLoadResourceChunk(g_path, id);
    rresUnloadResourceChunk(chunk);

    // Multi-chunk load: exercises the nextOffset linked-chunk walk. An input whose walk never
    // ends (multi_walk_ends above) skips only this call, and the harness rejects it after the
    // independent central-directory parse below has still run on it.
    int rejected = 0;
    if (multi_walk_ends(g_path, id, size)) {
        rresResourceMulti multi = rresLoadResourceMulti(g_path, id);
        rresUnloadResourceMulti(multi);
    } else {
        rejected = 1;
    }

    // Central directory: exercises the CDIR parse + dir-entry / fileName decode.
    rresCentralDir dir = rresLoadCentralDirectory(g_path);
    if (dir.count > 0 && dir.entries != NULL) {
        // Also drive the filename lookup helper against the first entry.
        (void)rresGetResourceId(dir, dir.entries[0].fileName);
    }
    rresUnloadCentralDirectory(dir);

    return rejected ? -1 : 0;
}
