// Manual mapper: maps the zero-import test DLL into a target process and
// starts its manual entry on a new thread. Dev tool; CRT use is fine here.
//
// Two mapping strategies, tried in order:
//   1. SEC_IMAGE section map  -> VAD reads MEM_IMAGE (stealthiest). Measured
//      on this system: cross-process execute mapping is DENIED (0xC0000022),
//      so strategy 2 is what actually runs here. Kept because other systems
//      or same-process mapping may allow it.
//   2. Private manual map     -> VirtualAllocEx + section copy + relocation
//      fixup + per-section protections. Works everywhere; VAD reads
//      MEM_PRIVATE, which is the tell the roadmap item (APC self-map) removes.
#include <windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstring>

typedef long(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, void*, PLARGE_INTEGER, ULONG, ULONG,
                                       HANDLE);
typedef long(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                          PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);

static unsigned long rd32(const unsigned char* p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) |
           ((unsigned long)p[3] << 24);
}
static unsigned short rd16(const unsigned char* p) {
    return (unsigned short)(p[0] | (p[1] << 8));
}

struct nocrt_config_wire {
    unsigned long long size;
    unsigned long cet_cpu_supported;
    unsigned long shadow_stack_active;
    unsigned long pt_active;
    unsigned long long image_base;
    unsigned long long entry_rva;
};

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("usage: inject.exe <pid> <dll-path> [--dump-log]\n");
        return 2;
    }
    const bool dump_log = (argc > 3 && strcmp(argv[3], "--dump-log") == 0);
    const DWORD pid = (DWORD)atoi(argv[1]);
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) {
        printf("inject: OpenProcess failed %lu\n", GetLastError());
        return 10;
    }
    HANDLE file = CreateFileA(argv[2], GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        printf("inject: cannot open dll\n");
        return 11;
    }
    const DWORD fsize = GetFileSize(file, nullptr);
    unsigned char* img = (unsigned char*)malloc(fsize);
    if (!img) {
        printf("inject: out of memory\n");
        return 11;
    }
    DWORD got = 0;
    if (!ReadFile(file, img, fsize, &got, nullptr) || got != fsize) {
        // A short read would map uninitialized heap into the target .text.
        printf("inject: SHORT READ got=%lu wanted=%lu\n", got, fsize);
        return 11;
    }

    const unsigned char* nt = img + rd32(img + 0x3C);
    const unsigned char* opt = nt + 24;
    const unsigned short opt_size = rd16(nt + 4 + 16);
    const unsigned short nsec = rd16(nt + 4 + 2);
    const unsigned long size_of_image = rd32(opt + 56);
    const unsigned long long image_base = rd32(opt + 24) | ((unsigned long long)rd32(opt + 28) << 32);
    const unsigned char* sec = opt + opt_size;
    const unsigned char* datadir = opt + 112;
    const unsigned long reloc_rva = rd32(datadir + 5 * 8);

    auto off_of = [&](unsigned long rva) -> unsigned long {
        for (unsigned short i = 0; i < nsec; ++i) {
            const unsigned char* e = sec + (unsigned long)i * 40;
            const unsigned long va = rd32(e + 12);
            const unsigned long vs = rd32(e + 8);
            const unsigned long rs = rd32(e + 16);
            const unsigned long rp = rd32(e + 20);
            if (rva >= va && rva < va + vs) {
                const unsigned long delta = rva - va;
                if (delta < rs && rp + delta < fsize) return rp + delta;
                return 0xFFFFFFFFu;  // virtual padding: no file bytes, never lie
            }
        }
        return 0xFFFFFFFFu;  // rva in no section: never lie
    };

    // Locate the manual entry export by name.
    const unsigned long exp_off = off_of(rd32(datadir));
    if (exp_off == 0xFFFFFFFFu) {
        printf("inject: export directory rva unresolvable in file\n");
        return 12;
    }
    const unsigned char* exp = img + exp_off;
    const unsigned long num_names = rd32(exp + 24);
    const unsigned long names_off = off_of(rd32(exp + 32));
    const unsigned long ords_off = off_of(rd32(exp + 36));
    const unsigned long funcs_off = off_of(rd32(exp + 28));
    if (names_off == 0xFFFFFFFFu || ords_off == 0xFFFFFFFFu || funcs_off == 0xFFFFFFFFu) {
        printf("inject: export tables unresolvable in file\n");
        return 12;
    }
    unsigned long manual_rva = 0;
    for (unsigned long i = 0; i < num_names; ++i) {
        const unsigned long no = off_of(rd32(img + names_off + i * 4));
        if (no == 0xFFFFFFFFu) continue;
        const char* name = (const char*)(img + no);
        if (strcmp(name, "NocrtManualEntry") == 0) {
            const unsigned short ord = rd16(img + ords_off + i * 2);
            manual_rva = rd32(img + funcs_off + (unsigned long)ord * 4);
            break;
        }
    }
    if (!manual_rva) {
        printf("inject: NocrtManualEntry export not found\n");
        return 13;
    }

    void* base = nullptr;
    bool image_mapped = false;

    // Strategy 1: SEC_IMAGE section map.
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto create_sec = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");
    auto map_view = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
    HANDLE section = nullptr;
    if (create_sec(&section, SECTION_MAP_EXECUTE, nullptr, nullptr, PAGE_EXECUTE_READ, SEC_IMAGE,
                   file) == 0) {
        SIZE_T view = 0;
        void* b = nullptr;
        if (map_view(section, proc, &b, 0, 0, nullptr, &view, 2 /*ViewUnmap*/, 0,
                     PAGE_EXECUTE_READ) == 0 && b) {
            base = b;
            image_mapped = true;
            printf("inject: SEC_IMAGE map at %p (MEM_IMAGE)\n", base);
        } else {
            printf("inject: SEC_IMAGE cross-process map denied - falling back\n");
        }
        CloseHandle(section);
    }

    // Strategy 2: private manual map with local relocation fixup.
    if (!base) {
        base = VirtualAllocEx(proc, nullptr, size_of_image, MEM_RESERVE | MEM_COMMIT,
                              PAGE_READWRITE);
        if (!base) {
            printf("inject: VirtualAllocEx failed %lu\n", GetLastError());
            return 2;
        }
        unsigned char* local = (unsigned char*)calloc(1, size_of_image);
        memcpy(local, img, fsize < size_of_image ? fsize : size_of_image);
        for (unsigned short i = 0; i < nsec; ++i) {
            const unsigned char* e = sec + (unsigned long)i * 40;
            const unsigned long va = rd32(e + 12);
            const unsigned long rs = rd32(e + 16);
            const unsigned long rp = rd32(e + 20);
            memcpy(local + va, img + rp, rs);
        }
        const long long delta = (long long)((unsigned long long)base - image_base);
        if (reloc_rva && delta) {
            const unsigned char* rel = local + off_of(reloc_rva);
            const unsigned char* rel_end = local + size_of_image;
            while (rel + 8 <= rel_end) {
                const unsigned long page_rva = rd32(rel);
                const unsigned long block_size = rd32(rel + 4);
                if (!block_size) break;
                const unsigned long entries = (block_size - 8) / 2;
                for (unsigned long e = 0; e < entries; ++e) {
                    const unsigned short ent = rd16(rel + 8 + e * 2);
                    const unsigned type = ent >> 12;
                    const unsigned long off = page_rva + (ent & 0xFFF);
                    if (type == 10) {
                        unsigned long long* p = (unsigned long long*)(local + off);
                        *p = (unsigned long long)((long long)*p + delta);
                    } else if (type == 3) {
                        unsigned long* p = (unsigned long*)(local + off);
                        *p = (unsigned long)((long long)*p + delta);
                    }
                }
                rel += block_size;
            }
        }
        if (!WriteProcessMemory(proc, base, local, size_of_image, nullptr)) {
            printf("inject: WriteProcessMemory failed %lu\n", GetLastError());
            return 2;
        }
        free(local);
        for (unsigned short i = 0; i < nsec; ++i) {
            const unsigned char* e = sec + (unsigned long)i * 40;
            const unsigned long va = rd32(e + 12);
            const unsigned long vs = rd32(e + 8);
            const unsigned long chars = rd32(e + 36);
            unsigned long prot = PAGE_READONLY;
            if (chars & 0x20000000) prot = (chars & 0x80000000) ? PAGE_READWRITE : PAGE_EXECUTE_READ;
            else if (chars & 0x80000000) prot = PAGE_READWRITE;
            DWORD old = 0;
            VirtualProtectEx(proc, (unsigned char*)base + va, vs, prot, &old);
        }
        printf("inject: private map at %p (MEM_PRIVATE, %lu bytes)\n", base, size_of_image);
    }
    CloseHandle(file);

    // Config block: CET/PT policy queried here with SDK enums, never assumed.
    nocrt_config_wire cfg = {};
    cfg.size = sizeof(cfg);
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, 7, 0);
    cfg.cet_cpu_supported = (regs[2] & (1 << 20)) ? 1 : 0;
    cfg.shadow_stack_active = 0;
    cfg.pt_active = 0;
    cfg.image_base = (unsigned long long)base;
    cfg.entry_rva = manual_rva;
    void* cfg_remote = VirtualAllocEx(proc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                      PAGE_READWRITE);
    if (!cfg_remote || !WriteProcessMemory(proc, cfg_remote, &cfg, sizeof(cfg), nullptr)) {
        printf("inject: config write failed\n");
        return 21;
    }

    const unsigned long long entry_va = (unsigned long long)base + manual_rva;
    HANDLE thread = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)entry_va,
                                       cfg_remote, 0, nullptr);
    if (!thread) {
        printf("inject: CreateRemoteThread failed %lu\n", GetLastError());
        return 30;
    }
    printf("inject: entry %p running (cet_cpu=%lu, image_mapped=%d)\n", (void*)entry_va,
           cfg.cet_cpu_supported, image_mapped ? 1 : 0);
    WaitForSingleObject(thread, 3000);
    DWORD tcode = 0;
    GetExitCodeThread(thread, &tcode);
    if (tcode == STILL_ACTIVE) {
        printf("inject: remote thread STILL RUNNING after wait (not an exit code)\n");
    } else {
        printf("inject: remote thread exit code 0x%08lX\n", tcode);
    }

    if (dump_log) {
        // Read the whole mapped image back and scan for the trace ring magic.
        unsigned char* local = (unsigned char*)malloc(size_of_image);
        if (local && ReadProcessMemory(proc, base, local, size_of_image, nullptr)) {
            long long ring = -1;
            for (unsigned long o = 0; o + 8 <= size_of_image; o += 8) {
                if (*(unsigned long long*)(local + o) == 0x304352545452434Ell) {
                    ring = o;
                    break;
                }
            }
            if (ring < 0) {
                printf("dump-log: no trace ring magic in mapped image (mapper never landed "
                       "it, or image_base wrong)\n");
            } else {
                const unsigned long head = *(unsigned long*)(local + ring + 24);
                const unsigned long cap = (unsigned long)*(unsigned long long*)(local + ring + 16);
                printf("dump-log: ring at base+0x%llX head=%lu cap=%lu\n", ring, head, cap);
                const unsigned long n = head < cap ? head : cap;
                for (unsigned long i = 0; i < n; ++i) {
                    const unsigned char* r = local + ring + 56 + (long long)i * 32;
                    printf("  rec%02lu site=%08lX code=%lu arg=%lu aux=%llX\n", i,
                           *(unsigned long*)(r + 12), *(unsigned long*)(r + 16),
                           *(unsigned long*)(r + 20), *(unsigned long long*)(r + 24));
                }
                if (n == 0) printf("  (ring present but empty: init ran, died before first "
                                   "record)\n");
            }
        } else {
            printf("dump-log: ReadProcessMemory of image failed\n");
        }
        free(local);
    }

    CloseHandle(thread);
    CloseHandle(proc);
    free(img);
    if (tcode == STILL_ACTIVE) return 31;
    if (tcode != 0) return 40;
    return 0;
}
