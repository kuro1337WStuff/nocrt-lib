// Metrics harness: emits machine-readable M-lines for the built images so
// proofs can be rebuilt from disk at any time. Runtime metrics (M4/M5/M6 from
// the demo, M8 from patscan --crt, M9 from the injected walk) are produced by
// those tools; this covers the static surface.
#include <windows.h>
#include <cstdio>
#include <cstring>

static unsigned long rd32(const unsigned char* p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) |
           ((unsigned long)p[3] << 24);
}
static unsigned short rd16(const unsigned char* p) {
    return (unsigned short)(p[0] | (p[1] << 8));
}

static unsigned char* load(const char* path, DWORD* size) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return nullptr;
    *size = GetFileSize(f, nullptr);
    unsigned char* b = (unsigned char*)malloc(*size);
    DWORD got = 0;
    ReadFile(f, b, *size, &got, nullptr);
    CloseHandle(f);
    return b;
}

static bool contains(const unsigned char* b, DWORD n, const char* needle) {
    const size_t L = strlen(needle);
    if (n < L) return false;
    for (DWORD i = 0; i + L <= n; ++i) {
        if (memcmp(b + i, needle, L) == 0) return true;
    }
    return false;
}

int main(int argc, char** argv) {
    const char* images[] = {"build\\nocrt-demo.exe", "build\\patscan.exe", "build\\nocrt-zero.exe",
                            "build\\testdll.dll"};
    for (int k = 0; k < 4; ++k) {
        DWORD n = 0;
        unsigned char* b = load(images[k], &n);
        if (!b) {
            printf("M0 image=%s status=missing\n", images[k]);
            continue;
        }
        const unsigned char* nt = b + rd32(b + 0x3C);
        const unsigned char* opt = nt + 24;
        const unsigned char* dd = opt + 112;
        // M1 import surface
        unsigned long mods = 0, funcs = 0;
        const unsigned long imp_rva = rd32(dd + 1 * 8);
        if (imp_rva) {
            const unsigned short nsec = rd16(nt + 4 + 2);
            const unsigned short opt_size = rd16(nt + 4 + 16);
            const unsigned char* sec = opt + opt_size;
            auto off_of = [&](unsigned long rva) -> unsigned long {
                for (unsigned short i = 0; i < nsec; ++i) {
                    const unsigned char* e = sec + (unsigned long)i * 40;
                    const unsigned long va = rd32(e + 12);
                    const unsigned long rs = rd32(e + 16);
                    const unsigned long rp = rd32(e + 20);
                    if (rva >= va && rva < va + rs) return rp + (rva - va);
                }
                return rva;
            };
            const unsigned char* d = b + off_of(imp_rva);
            while (rd32(d) || rd32(d + 12)) {
                ++mods;
                const unsigned long int_rva = rd32(d + 16);
                if (int_rva) {
                    const unsigned char* t = b + off_of(int_rva);
                    while (rd32(t) || (sizeof(void*) == 8 && rd32(t + 4))) {
                        ++funcs;
                        t += 8;
                    }
                }
                d += 20;
            }
        }
        printf("M1 image=%s import_modules=%lu import_functions=%lu\n", images[k], mods, funcs);
        // M2 CRT references
        printf("M2 image=%s crt_strings=%d\n", images[k],
               (contains(b, n, "msvcrt") || contains(b, n, "ucrtbase") ||
                contains(b, n, "vcruntime"))
                   ? 1
                   : 0);
        // M3 protected plaintext absent
        printf("M3 image=%s plaintext_polymorphic=%d plaintext_hardened=%d\n", images[k],
               contains(b, n, "polymorphic") ? 1 : 0, contains(b, n, "hardened") ? 1 : 0);
        // M7 relocatability
        printf("M7 image=%s reloc_rva=0x%lX reloc_size=0x%lX\n", images[k], rd32(dd + 5 * 8),
               rd32(dd + 5 * 8 + 4));
        // M10 size
        printf("M10 image=%s bytes=%lu\n", images[k], n);
        free(b);
    }
    return 0;
}
