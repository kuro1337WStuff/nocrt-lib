#pragma once

#include "nocrt/nocrt.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

// In-image trace ring: fixed .bss storage, pure stores, no syscalls, no
// handles, no stdout. Survives thread death and ExitProcess; the injector
// reads it back with ReadProcessMemory (--dump-log), even from a dead host.
// This is what makes "silent failure" answerable: ring empty but magic
// present = init ran and died before first write; no magic anywhere = the
// mapper never landed the image.
//
// Codes are numeric only: strings are a plaintext oracle and never ship here.

namespace nocrt {

constexpr unsigned long long kTraceMagic = 0x304352545452434Ell;  // 'NCRTTRC0'
constexpr unsigned long long kTraceAbi = 1;
#ifndef NOCRT_TRACE_SLOTS
#define NOCRT_TRACE_SLOTS 64
#endif

struct trace_rec {
    unsigned long long tsc;
    unsigned long seq;
    unsigned long site;   // fnv1a(__FILE__ ":" __LINE__), folded at compile time
    unsigned long code;   // nocrt::status or stage id
    unsigned long arg;    // win32 error / match count / low32 of address
    unsigned long long aux;
};

struct trace_ring {
    unsigned long long magic;
    unsigned long long abi;
    unsigned long long capacity;
    volatile unsigned long head;
    unsigned long long build_id;
    unsigned long long image_base;
    unsigned long tid;
    trace_rec rec[NOCRT_TRACE_SLOTS];
};

inline trace_ring g_trace;

constexpr unsigned long long site_id(const char* file, unsigned long line) {
    unsigned long long h = 0xCBF29CE484222325ull;
    for (nocrt_size i = 0; file[i]; ++i) {
        h ^= (unsigned char)file[i];
        h *= 0x100000001B3ull;
    }
    h ^= 0xFF;
    h *= 0x100000001B3ull;
    const unsigned long long l = line;
    for (nocrt_size i = 0; i < 8; ++i) {
        h ^= (unsigned char)((l >> (i * 8)) & 0xFF);
        h *= 0x100000001B3ull;
    }
    return h;
}

inline void trace_init(unsigned long long image_base, unsigned long long build_id) {
    g_trace.magic = kTraceMagic;
    g_trace.abi = kTraceAbi;
    g_trace.capacity = NOCRT_TRACE_SLOTS;
    g_trace.head = 0;
    g_trace.build_id = build_id;
    g_trace.image_base = image_base;
    g_trace.tid = *(unsigned long*)((unsigned char*)__readgsqword(0x30) + 0x48);
}

inline void trace_write(unsigned long site, unsigned long code, unsigned long arg,
                        unsigned long long aux) {
    if (g_trace.magic != kTraceMagic) return;
    const unsigned long i = g_trace.head;
    if (i >= g_trace.capacity) return;
    trace_rec& r = g_trace.rec[i];
    r.tsc = __rdtsc();
    r.seq = i;
    r.site = site;
    r.code = code;
    r.arg = arg;
    r.aux = aux;
    g_trace.head = i + 1;
}

} // namespace nocrt

#define NOCRT_TR(site_code, arg, aux)                                                          \
    ::nocrt::trace_write(::nocrt::site_id(__FILE__, __LINE__), (site_code), (arg), (aux))
