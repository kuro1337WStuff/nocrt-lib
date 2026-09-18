// Host-side stackwalk tool: walks the current stack the way an anti-tamper
// scanner would and classifies each frame as backed by a known module or not.
// Unbacked frames are the injection tell; run it inside the host before and
// after injection to see the delta.
#include <windows.h>
#include <psapi.h>
#include <cstdio>

#pragma comment(lib, "psapi.lib")

typedef unsigned long(__stdcall* RtlWalkFrameChain_t)(void** frames, unsigned long count,
                                                      unsigned long flags);

int main() {
    const auto walk = (RtlWalkFrameChain_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                          "RtlWalkFrameChain");
    if (!walk) {
        printf("STACKWALK: RtlWalkFrameChain unavailable\n");
        return 2;
    }
    void* frames[64];
    const unsigned long n = walk(frames, 64, 0);
    HMODULE mods[256];
    DWORD needed = 0;
    EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed);
    const DWORD count = needed / sizeof(HMODULE);
    unsigned long unbacked = 0;
    printf("STACKWALK frames=%lu modules=%lu\n", n, count);
    for (unsigned long i = 0; i < n; ++i) {
        bool backed = false;
        for (DWORD m = 0; m < count; ++m) {
            MODULEINFO mi;
            if (GetModuleInformation(GetCurrentProcess(), mods[m], &mi, sizeof(mi))) {
                const unsigned long long a = (unsigned long long)frames[i];
                const unsigned long long lo = (unsigned long long)mi.lpBaseOfDll;
                if (a >= lo && a < lo + mi.SizeOfImage) {
                    backed = true;
                    break;
                }
            }
        }
        if (!backed) ++unbacked;
        printf("frame[%lu]=%p %s\n", i, frames[i], backed ? "backed" : "UNBACKED");
    }
    printf("STACKWALK unbacked=%lu\n", unbacked);
    return 0;
}
