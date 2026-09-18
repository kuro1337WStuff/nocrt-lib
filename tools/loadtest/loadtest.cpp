// Loader-mode test harness: a normal CRT host that LoadLibrary's the nocrt
// test DLL. Loaded (loader-mapped) operation is the stealth-win default for a
// defensive tool (MEM_IMAGE, PEB entry, real FILE_OBJECT, legitimate thread
// start addresses) and gives repeatable end-to-end verification without the
// manual mapper.
#include <windows.h>
#include <cstdio>

__declspec(noinline) long long host_target(long long x) {
    return x * 0x1234567 + 0x7654321;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        HMODULE m = LoadLibraryA(argv[1]);
        printf("loadtest: LoadLibrary %s = %p err %lu\n", argv[1], (void*)m, GetLastError());
        fflush(stdout);
        if (m) {
            using kick_t = unsigned long(__stdcall*)(void*);
            auto kick = (kick_t)GetProcAddress(m, "NocrtManualEntry");
            printf("loadtest: NocrtManualEntry = %p\n", (void*)kick);
            fflush(stdout);
            if (kick) kick(nullptr);
        }
    }
    printf("LOADTEST PID %lu\n", GetCurrentProcessId());
    fflush(stdout);
    for (int i = 0; i < 40; ++i) {
        const long long r = host_target(i);
        printf("host_target(%d)=%lld\n", i, r);
        if (r == 1337) printf("CONTROL FLOW CHANGED\n");
        fflush(stdout);
        Sleep(500);
    }
    return 0;
}
