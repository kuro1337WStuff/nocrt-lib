#include "nocrt/nocrt.h"

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
