// Post-link metadata stripper: removes the Rich header and every debug
// directory entry (CodeView PDB path, POGO/coffgrp, VC_FEATURE, ILTCG) from a
// PE image in place. Dev tool; CRT use is fine here.
#include <cstdio>
#include <cstring>
#include <cstdlib>

static unsigned long rd32(const unsigned char* p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) |
           ((unsigned long)p[3] << 24);
}
static void wr32(unsigned char* p, unsigned long v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("usage: strip.exe <pe-image>\n");
        return 2;
    }
    FILE* f = fopen(argv[1], "r+b");
    if (!f) {
        printf("strip: cannot open %s\n", argv[1]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* b = (unsigned char*)malloc((size_t)size);
    if (!b || fread(b, 1, (size_t)size, f) != (size_t)size) {
        fclose(f);
        return 2;
    }

    unsigned long stripped = 0;

    // --- Rich header: plain 'Rich' magic followed by the XOR key; the 'DanS'
    // marker before it is XOR-encoded with that key.
    unsigned long lfanew = rd32(b + 0x3C);
    if (lfanew < 8 || lfanew > (unsigned long)size) {
        fclose(f);
        free(b);
        return 2;
    }
    for (unsigned long i = 8; i + 8 < lfanew; ++i) {
        if (b[i] == 'R' && b[i + 1] == 'i' && b[i + 2] == 'c' && b[i + 3] == 'h') {
            unsigned long key = rd32(b + i + 4);
            unsigned long dans = 0;
            for (unsigned long j = i; j >= 4; j -= 4) {
                if ((rd32(b + j) ^ key) == 0x536E6144ul) {
                    dans = j;
                    break;
                }
            }
            if (dans) {
                unsigned long span = (i + 8) - dans;
                memset(b + dans, 0, span);
                stripped += span;
                printf("strip: rich header zeroed (%lu bytes @0x%lX)\n", span, dans);
            }
            break;
        }
    }

    // --- Debug directories: zero each entry's raw payload, then the
    // directory itself, then clear the data directory slot.
    unsigned char* nt = b + lfanew;
    unsigned char* opt = nt + 24;
    unsigned short magic = (unsigned short)(opt[0] | (opt[1] << 8));
    unsigned char* datadir = opt + (magic == 0x20B ? 112 : 96);
    unsigned long dbg_rva = rd32(datadir + 6 * 8);
    unsigned long dbg_size = rd32(datadir + 6 * 8 + 4);
    if (dbg_rva && dbg_size) {
        // File offset of the directory: walk sections (raw -> virtual).
        unsigned char* fh = nt + 4;
        unsigned short nsec = (unsigned short)(fh[2] | (fh[3] << 8));
        unsigned short opt_size = (unsigned short)(fh[16] | (fh[17] << 8));
        unsigned char* sec = opt + opt_size;
        unsigned long dbg_off = 0;
        for (unsigned short s = 0; s < nsec; ++s) {
            unsigned char* e = sec + (unsigned long)s * 40;
            unsigned long va = rd32(e + 12);
            unsigned long raw_size = rd32(e + 16);
            unsigned long raw_ptr = rd32(e + 20);
            if (dbg_rva >= va && dbg_rva < va + raw_size) {
                dbg_off = raw_ptr + (dbg_rva - va);
                break;
            }
        }
        if (dbg_off && dbg_off + dbg_size <= (unsigned long)size) {
            unsigned long count = dbg_size / 28;
            for (unsigned long d = 0; d < count; ++d) {
                unsigned char* e = b + dbg_off + d * 28;
                unsigned long raw_ptr = rd32(e + 20);
                unsigned long raw_len = rd32(e + 16);
                if (raw_ptr && raw_len && raw_ptr + raw_len <= (unsigned long)size) {
                    memset(b + raw_ptr, 0, raw_len);
                    stripped += raw_len;
                }
            }
            memset(b + dbg_off, 0, dbg_size);
            stripped += dbg_size;
            printf("strip: debug dirs zeroed (%lu entries, %lu bytes @0x%lX)\n", count, dbg_size,
                   dbg_off);
        }
        wr32(datadir + 6 * 8, 0);
        wr32(datadir + 6 * 8 + 4, 0);
    }

    fseek(f, 0, SEEK_SET);
    fwrite(b, 1, (size_t)size, f);
    fclose(f);
    free(b);
    printf("strip: %s total zeroed %lu bytes\n", argv[1], stripped);
    return 0;
}
