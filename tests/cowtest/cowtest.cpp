// COW experiment (research fold-in 5, Step 1): map a signed system image via
// SEC_IMAGE in our own process, write one byte into a .text page, and report
// what VirtualQuery says about the written page vs an untouched page.
// Answers: does a written image page report MEM_PRIVATE? Does AllocationBase
// stay at the image base? Does the section name survive?
#include <windows.h>
#include <psapi.h>
#include <cstdio>

#pragma comment(lib, "psapi.lib")

typedef long(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, void*, PLARGE_INTEGER, ULONG, ULONG,
                                       HANDLE);
typedef long(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                          PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);

static unsigned long rd32(const unsigned char* p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) |
           ((unsigned long)p[3] << 24);
}

static void dump(const char* tag, const void* addr) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery(addr, &mbi, sizeof(mbi))) {
        printf("%s: VirtualQuery failed\n", tag);
        return;
    }
    wchar_t name[MAX_PATH] = {};
    const DWORD nl = GetMappedFileNameW(GetCurrentProcess(), (LPVOID)addr, name, MAX_PATH);
    printf("%s: Type=0x%lX Protect=0x%lX AllocProtect=0x%lX Base=%p AllocBase=%p name=%ls\n", tag,
           mbi.Type, mbi.Protect, mbi.AllocationProtect, mbi.BaseAddress, mbi.AllocationBase,
           nl ? name : L"(none)");
}

int main() {
    // Part 1: is SEC_IMAGE mapping available at all on this system?
    const char* path = "C:\\Windows\\System32\\winmm.dll";
    HANDLE file = CreateFileA(path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        auto create_sec = (NtCreateSection_t)GetProcAddress(ntdll, "NtCreateSection");
        auto map_view = (NtMapViewOfSection_t)GetProcAddress(ntdll, "NtMapViewOfSection");
        HANDLE section = nullptr;
        long st = create_sec(&section, SECTION_MAP_EXECUTE, nullptr, nullptr, PAGE_EXECUTE_READ,
                             0x1000000 /*SEC_IMAGE*/, file);
        if (st != 0) {
            printf("cowtest: NtCreateSection denied 0x%08lX\n", (unsigned long)st);
        } else {
            void* base = nullptr;
            SIZE_T view = 0;
            st = map_view(section, GetCurrentProcess(), &base, 0, 0, nullptr, &view, 1, 0,
                          PAGE_EXECUTE_READ);
            printf("cowtest: SEC_IMAGE map status 0x%08lX base %p\n", (unsigned long)st, base);
            if (st == 0) {
                const unsigned char* b = (const unsigned char*)base;
                const unsigned char* nt = b + rd32(b + 0x3C);
                const unsigned char* opt = nt + 24;
                const unsigned short opt_size = (unsigned short)(nt[4 + 16] | (nt[4 + 17] << 8));
                const unsigned char* sec = opt + opt_size;
                unsigned char* target = (unsigned char*)base + rd32(sec + 12) + 0x10;
                dump("mapped-before ", target);
                DWORD o = 0;
                if (VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &o)) {
                    *target = *target;
                    VirtualProtect(target, 1, o, &o);
                    dump("mapped-after  ", target);
                }
            }
            CloseHandle(section);
        }
        CloseHandle(file);
    }

    // Part 2: COW behaviour on an already-loaded image (no mapping needed).
    unsigned char* kbase = (unsigned char*)GetModuleHandleA("kernel32.dll");
    if (!kbase) {
        printf("cowtest: no kernel32\n");
        return 2;
    }
    const unsigned char* knt = kbase + rd32(kbase + 0x3C);
    const unsigned char* kopt = knt + 24;
    const unsigned short kopt_size = (unsigned short)(knt[4 + 16] | (knt[4 + 17] << 8));
    const unsigned char* ksec = kopt + kopt_size;
    unsigned char* target = kbase + rd32(ksec + 12) + 0x10;
    unsigned char* untouched = kbase + rd32(ksec + 12) + 0x200;
    dump("loaded-before ", target);
    DWORD old = 0;
    if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &old)) {
        printf("cowtest: VirtualProtect failed %lu\n", GetLastError());
        return 2;
    }
    *target = *target;  // store triggers COW regardless of value
    VirtualProtect(target, 1, old, &old);
    dump("loaded-after  ", target);
    dump("loaded-untchd ", untouched);
    return 0;
}
