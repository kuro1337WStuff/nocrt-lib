#pragma once

#include "nocrt/nocrt.h"
#include "nocrt/lazy.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

// Stack-walking countermeasures and policy detection.
//
// The hardware features that make kernel-level stack walking authoritative
// are Intel CET shadow stacks (BIOS: Control-flow Enforcement / Intel CET)
// and Intel PT. We assume them OFF in the lab but NEVER trust that: the
// injector queries the real per-process policy and passes it in here, and the
// CPU capability is read from CPUID. If shadow stacks are active, return-
// address spoofing would raise a control-protection fault, so policy gates
// the spoofing paths and prefers zero-write hooks.
//
// Honest limit: a kernel-mode walker backed by CET shadow stacks cannot be
// fully spoofed from user mode. What we can win is unwind-based and
// frame-chain walking, by controlling whether our region unwinds at all.

namespace nocrt {

// Injector-written configuration. Single global pointer = the whole lib's
// mutable state (ephemeral-state rule); zeroed after init by the consumer.
struct nocrt_config {
    unsigned long long size;
    unsigned long cet_cpu_supported;
    unsigned long shadow_stack_active;
    unsigned long pt_active;
    unsigned long long image_base;
    unsigned long long entry_rva;
};

inline nocrt_config* g_config;

inline bool cet_cpu_supported() {
#if defined(_MSC_VER)
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, 7, 0);
    return (regs[2] & (1 << 20)) != 0;
#else
    return false;
#endif
}

// Shadow stacks active for this process? Config is authoritative; CPU support
// alone does not enable it.
inline bool shadow_stacks_active() {
    if (!g_config) return cet_cpu_supported();
    return g_config->shadow_stack_active != 0;
}

using RtlAddFunctionTable_t = unsigned char(__stdcall*)(void* tables, unsigned long count,
                                                        unsigned long long base);
using RtlDeleteFunctionTable_t = unsigned char(__stdcall*)(void* tables);

// Analysis mode: register dynamic unwind info so walkers unwind our region
// cleanly. Stealth mode: leave it unregistered so a walker stalls here.
inline bool register_unwind(void* tables, unsigned long count, unsigned long long base) {
    const auto f = (RtlAddFunctionTable_t)NOCRT_FN("RtlAddFunctionTable");
    return f != nullptr && f(tables, count, base) != 0;
}

inline bool unregister_unwind(void* tables) {
    const auto f = (RtlDeleteFunctionTable_t)NOCRT_FN("RtlDeleteFunctionTable");
    return f != nullptr && f(tables) != 0;
}

// Walk the current stack the way a host-side analyst (or the sample's own
// anti-tamper code) would, and classify each frame as backed by a known
// module or not. Unbacked frames are the injection tell.
inline nocrt_size walk_frames(unsigned long long* out, nocrt_size count) {
    const auto f = (unsigned long(__stdcall*)(void**, unsigned long, unsigned long))NOCRT_FN(
        "RtlWalkFrameChain");
    if (!f) return 0;
    return f((void**)out, (unsigned long)count, 0);
}

inline bool frame_backed(unsigned long long addr) {
    for (nocrt_size i = 0;; ++i) {
        const unsigned char* base = module_base(i);
        if (!base) break;
        const unsigned long long sz = module_size(base);
        if (addr >= (unsigned long long)base && addr < (unsigned long long)base + sz) return true;
    }
    return false;
}

inline nocrt_size count_unbacked_frames(unsigned long long* frames, nocrt_size count) {
    nocrt_size unbacked = 0;
    for (nocrt_size i = 0; i < count; ++i) {
        if (!frame_backed(frames[i])) ++unbacked;
    }
    return unbacked;
}

} // namespace nocrt
