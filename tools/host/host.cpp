// Normal CRT console host: the test bench a zero-import DLL gets mapped into.
#include <windows.h>
#include <cstdio>

__declspec(noinline) long long host_target(long long x) {
    return x * 0x1234567 + 0x7654321;
}

int main() {
    printf("HOST PID %lu\n", GetCurrentProcessId());
    fflush(stdout);
    for (int i = 0; i < 40; ++i) {
        const long long r = host_target(i);
        printf("host_target(%d)=%lld\n", i, r);
        if (r == 1337) {
            printf("CONTROL FLOW CHANGED\n");
        }
        fflush(stdout);
        Sleep(500);
    }
    return 0;
}
