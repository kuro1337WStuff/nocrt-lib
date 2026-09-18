#include "nocrt/nocrt.h"

// Replaces the CRT startup. Linked as the image entry point via /ENTRY.
extern "C" void __cdecl nocrt_entry() {
    const int code = nocrt_main();
    ExitProcess((nocrt_dword)code);
}
