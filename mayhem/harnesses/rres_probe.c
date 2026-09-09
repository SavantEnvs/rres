// rres_probe.c — known-answer behavioral probe for the rres parser (the test.sh oracle).
//
// Built with the project's NORMAL flags (no sanitizer, no -gdwarf-3) by build.sh, and RUN by
// mayhem/test.sh, which greps EXACT expected values out of this program's stdout. It parses a
// fixed committed seed (mayhem/rres_fuzz/testsuite/seed_cdir.rres, argv[1]) through the real
// loader API and prints the parsed fields. If the program is neutered to exit(0) (the sabotage
// shim), nothing is printed and every grep in test.sh fails — which is exactly the behavioral
// property the gate requires.

#include <stdio.h>
#include <string.h>

#define RRES_SUPPORT_LOG_INFO 0
#define RRES_IMPLEMENTATION
#include "rres.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <seed_cdir.rres>\n", argv[0]); return 2; }
    const char *path = argv[1];

    // 1) All chunk-info records: seed_cdir.rres has exactly 2 chunks (RAWD then CDIR).
    unsigned int count = 0;
    rresResourceChunkInfo *infos = rresLoadResourceChunkInfoAll(path, &count);
    printf("COUNT=%u\n", count);
    if (infos != NULL && count >= 1)
        printf("FOURCC0=%c%c%c%c\n", infos[0].type[0], infos[0].type[1], infos[0].type[2], infos[0].type[3]);
    if (infos != NULL && count >= 2)
        printf("FOURCC1=%c%c%c%c\n", infos[1].type[0], infos[1].type[1], infos[1].type[2], infos[1].type[3]);
    unsigned int rid = (infos && count > 0) ? infos[0].id : 0;
    RRES_FREE(infos);
    printf("DATATYPE0=%u\n", rresGetDataType((const unsigned char *)"RAWD"));  // expect 1

    // 2) Load the RAWD chunk: CRC32 gate passes -> propCount=1, props[0]=3, raw="abc".
    rresResourceChunk chunk = rresLoadResourceChunk(path, rid);
    printf("PROPCOUNT=%u\n", chunk.data.propCount);
    if (chunk.data.propCount >= 1) printf("PROP0=%u\n", chunk.data.props[0]);
    if (chunk.data.raw != NULL) printf("RAW=%.3s\n", (char *)chunk.data.raw);
    rresUnloadResourceChunk(chunk);

    // 3) Central directory: 1 entry pointing at "data.txt".
    rresCentralDir dir = rresLoadCentralDirectory(path);
    printf("CDCOUNT=%u\n", dir.count);
    if (dir.count >= 1 && dir.entries != NULL) printf("CDNAME=%s\n", dir.entries[0].fileName);
    rresUnloadCentralDirectory(dir);

    return 0;
}
