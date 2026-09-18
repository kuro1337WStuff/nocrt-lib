#include "nocrt/nocrt.h"

extern "C" int nocrt_main() {
    const char banner[] = "nocrt: alive - no CRT linked\r\n";
    nocrt::out(banner, sizeof(banner) - 1);

    char buf[32];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "memcpy/memset/strlen work: ", 27);
    nocrt::out(buf, 27);

    const char* probe = "freestanding";
    char copy[16];
    memcpy(copy, probe, strlen(probe) + 1);
    if (strcmp(copy, "freestanding") == 0 && strncmp(copy, "free", 4) == 0 &&
        memcmp(copy, probe, 12) == 0 && memmove(copy + 1, copy, 12) != nullptr) {
        nocrt::out("ok\r\n", 4);
        return 0;
    }
    nocrt::err("self-test failed\r\n", 18);
    return 1;
}
