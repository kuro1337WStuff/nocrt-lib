#include "nocrt/nocrt.h"

// These names are MSVC intrinsics by default; #pragma function makes them
// ordinary functions so we can define them and keep /Oi enabled elsewhere
// (lazy.h needs __readgsqword).
#pragma function(memset, memcpy, memmove, memcmp, strlen, strcmp)

// Byte-wise implementations. Deliberately not intrinsics: these must exist
// as real symbols so implicit compiler-emitted calls link with /NODEFAULTLIB.

extern "C" void* __cdecl memset(void* dst, int value, nocrt_size n) {
    unsigned char* d = (unsigned char*)dst;
    unsigned char v = (unsigned char)value;
    for (nocrt_size i = 0; i < n; ++i) d[i] = v;
    return dst;
}

extern "C" void* __cdecl memcpy(void* dst, const void* src, nocrt_size n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (nocrt_size i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

extern "C" void* __cdecl memmove(void* dst, const void* src, nocrt_size n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d < s) {
        for (nocrt_size i = 0; i < n; ++i) d[i] = s[i];
    } else {
        for (nocrt_size i = n; i-- > 0;) d[i] = s[i];
    }
    return dst;
}

extern "C" int __cdecl memcmp(const void* a, const void* b, nocrt_size n) {
    const unsigned char* pa = (const unsigned char*)a;
    const unsigned char* pb = (const unsigned char*)b;
    for (nocrt_size i = 0; i < n; ++i) {
        if (pa[i] != pb[i]) return pa[i] < pb[i] ? -1 : 1;
    }
    return 0;
}

extern "C" nocrt_size __cdecl strlen(const char* s) {
    nocrt_size n = 0;
    while (s[n]) ++n;
    return n;
}

extern "C" int __cdecl strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (unsigned char)*a - (unsigned char)*b;
}

extern "C" int __cdecl strncmp(const char* a, const char* b, nocrt_size n) {
    for (nocrt_size i = 0; i < n; ++i) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        if (!a[i]) return 0;
    }
    return 0;
}

#ifndef NOCRT_ZERO_IMPORT
#define NOCRT_ZERO_IMPORT 0
#endif

#if NOCRT_ZERO_IMPORT
#include "nocrt/lazy.h"
#endif

namespace nocrt {
namespace {

api_table g_api;
bool g_api_ready = false;

api_table make_api() {
    api_table t = {};
#if NOCRT_ZERO_IMPORT
    constexpr unsigned long long seed = 0xA5A5C3C35A5A3C3Cull;
    t.get_std_handle = (decltype(t.get_std_handle))lazy_resolve(
        str_hash("GetStdHandle", seed), seed);
    t.write_file = (decltype(t.write_file))lazy_resolve(
        str_hash("WriteFile", seed), seed);
    t.exit_process = (decltype(t.exit_process))lazy_resolve(
        str_hash("ExitProcess", seed), seed);
    t.get_command_line_a = (decltype(t.get_command_line_a))lazy_resolve(
        str_hash("GetCommandLineA", seed), seed);
#else
    t.get_std_handle = GetStdHandle;
    t.write_file = WriteFile;
    t.exit_process = ExitProcess;
    t.get_command_line_a = GetCommandLineA;
#endif
    return t;
}

} // namespace

// No CRT startup exists, so this cannot rely on static initializers: the
// table lives in .bss and is filled on first use.
api_table& api() {
    if (!g_api_ready) {
        g_api = make_api();
        g_api_ready = true;
    }
    return g_api;
}

} // namespace nocrt
