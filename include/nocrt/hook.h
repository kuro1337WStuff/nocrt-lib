#pragma once

#include "nocrt/nocrt.h"
#include "nocrt/ldis.h"

// Production inline-hook engine (research fold-in 6).
//
// Design rules adopted from the engine survey:
//  - one shared trampoline region, allocated RW within +/-1GB of targets,
//    flipped to RX once at first install (never RWX, no cyclic churn);
//  - E9 rel32 (5 bytes) at the target; stolen instructions are whole
//    instructions chosen by the restricted length decoder, which REFUSES
//    RIP-relative operands and branches inside the stolen range;
//  - threads parked inside the patched bytes are suspended and their Rip is
//    remapped into the trampoline (Detours rAlign-style);
//  - every trampoline registers a dynamic function table so stack walks pass
//    through instead of truncating (truncation is itself a detection);
//  - FlushInstructionCache after every code write.

namespace nocrt {

constexpr nocrt_size kHookRegionSize = 0x10000;
constexpr nocrt_size kHookSlotSize = 64;

struct nocrt_hook {
    unsigned char* target;
    unsigned char* slot;
    unsigned char saved[16];
    unsigned char expect[8];  // our exact patch bytes, for sound verification
    nocrt_size stolen;
    bool active;
    void* unwind_table;
};

namespace hook_detail {

inline unsigned char* g_region;
inline nocrt_size g_region_used;
inline bool g_region_rx;

using VirtualProtect_t = int(__stdcall*)(void*, nocrt_size, unsigned long, unsigned long*);
using VirtualAlloc_t = void*(__stdcall*)(void*, nocrt_size, unsigned long, unsigned long);
using FlushIC_t = int(__stdcall*)(void*, void*, nocrt_size);
using Snap_t = void*(__stdcall*)(unsigned long, unsigned long);
using ThreadFirst_t = int(__stdcall*)(void*, void*);
using ThreadNext_t = int(__stdcall*)(void*, void*);
using OpenThread_t = void*(__stdcall*)(unsigned long, int, unsigned long);
using Suspend_t = unsigned long(__stdcall*)(void*);
using Resume_t = unsigned long(__stdcall*)(void*);
using GetCtx_t = int(__stdcall*)(void*, void*);
using SetCtx_t = int(__stdcall*)(void*, void*);
using Close_t = int(__stdcall*)(void*);

struct thread_entry {
    unsigned long dummy1[2];
    unsigned long th32ThreadID;
    unsigned long th32OwnerProcessID;
};

inline unsigned long self_pid() {
    // TEB->ClientId.UniqueProcess via intrinsic-free read: PEB not needed.
    return *(unsigned long*)((unsigned char*)__readgsqword(0x30) + 0x40);
}

inline unsigned long self_tid() {
    return *(unsigned long*)((unsigned char*)__readgsqword(0x30) + 0x48);
}

// Suspend every other thread in the process; returns count suspended.
inline nocrt_size suspend_others(void** handles, nocrt_size cap) {
    const auto snap = (Snap_t)NOCRT_FN("CreateToolhelp32Snapshot");
    const auto tf = (ThreadFirst_t)NOCRT_FN("Thread32First");
    const auto tn = (ThreadNext_t)NOCRT_FN("Thread32Next");
    const auto ot = (OpenThread_t)NOCRT_FN("OpenThread");
    const auto sus = (Suspend_t)NOCRT_FN("SuspendThread");
    if (!snap || !tf || !tn || !ot || !sus) return 0;
    // THREADENTRY32: dwSize@0, cntUsage@4, th32ThreadID@8, th32OwnerProcessID@12
    void* h = snap(4 /*TH32CS_SNAPTHREAD*/, 0);
    if (h == (void*)-1) return 0;
    unsigned char te[32] = {};
    *(unsigned long*)te = 32;
    nocrt_size n = 0;
    const unsigned long pid = self_pid();
    const unsigned long tid = self_tid();
    if (tf(h, te)) {
        do {
            const unsigned long owner = *(unsigned long*)(te + 12);
            const unsigned long id = *(unsigned long*)(te + 8);
            if (owner != pid || id == tid) continue;
            void* th = ot(0x0002 | 0x0040 | 0x0080 /*SUSPEND/RESUME/GET_SET_CONTEXT*/, 0, id);
            if (!th) continue;
            if (sus(th) != (unsigned long)-1 && n < cap) handles[n++] = th;
            else {
                const auto cl = (Close_t)NOCRT_FN("CloseHandle");
                if (cl) cl(th);
            }
        } while (tn(h, te));
    }
    const auto cl = (Close_t)NOCRT_FN("CloseHandle");
    if (cl) cl(h);
    return n;
}

inline void resume_all(void** handles, nocrt_size n) {
    const auto res = (Resume_t)NOCRT_FN("ResumeThread");
    const auto cl = (Close_t)NOCRT_FN("CloseHandle");
    for (nocrt_size i = 0; i < n; ++i) {
        if (res) res(handles[i]);
        if (cl) cl(handles[i]);
    }
}

// Remap parked Rips: [target, target+5) -> slot+(rip-target).
inline void fixup_threads(void** handles, nocrt_size n, unsigned char* target,
                          unsigned char* slot) {
    const auto gc = (GetCtx_t)NOCRT_FN("GetThreadContext");
    const auto sc = (SetCtx_t)NOCRT_FN_RAW("SetThreadContext");
    if (!gc || !sc) return;
    unsigned char ctx[0x4D0 + 16] = {};
    *(unsigned long*)(ctx + 0x30) = 0x00100000 | 0x00000001 | 0x00000002 | 0x00000008;
    for (nocrt_size i = 0; i < n; ++i) {
        if (!gc(handles[i], ctx)) continue;
        unsigned long long rip = *(unsigned long long*)(ctx + 0xF8);
        if (rip >= (unsigned long long)target && rip < (unsigned long long)target + 5) {
            *(unsigned long long*)(ctx + 0xF8) =
                (unsigned long long)slot + (rip - (unsigned long long)target);
            sc(handles[i], ctx);
        }
    }
}

inline unsigned char* ensure_region(unsigned char* near_target) {
    if (g_region) return g_region;
    const auto va = (VirtualAlloc_t)NOCRT_FN("VirtualAlloc");
    if (!va) return nullptr;
    unsigned char* page_target = (unsigned char*)((unsigned long long)near_target & ~0xFFFull);
    for (long long off = -0x38000000LL; off <= 0x38000000LL; off += 0x00800000LL) {
        unsigned char* hint = page_target + off;
        if ((unsigned long long)hint < 0x10000) continue;
        unsigned char* p = (unsigned char*)va(hint, kHookRegionSize, 0x1000 | 0x2000, 0x04);
        if (p) {
            const long long d = (long long)(p - (near_target + 5));
            if (d < -2147483648LL || d > 2147483647LL) continue;
            g_region = p;
            g_region_used = 0;
            return p;
        }
    }
    return nullptr;
}

// UNWIND_INFO builder for the trampoline: mirrors the stolen stack ops.
inline nocrt_size build_unwind(unsigned char* out, const nocrt_prologue& pr) {
    unsigned char codes[8];
    nocrt_size nc = 0;
    if (pr.alloc_size) {
        if (pr.alloc_size <= 64 && (pr.alloc_size % 8) == 0) {
            codes[nc] = (unsigned char)(((pr.alloc_size - 8) / 8) << 4 | 1);  // op=ALLOC_SMALL
            codes[nc + 1] = (unsigned char)pr.alloc_offset;
            nc += 2;
        } else if (pr.alloc_size < 512 * 1024) {
            codes[nc] = (unsigned char)(0 << 4 | 2);  // op=ALLOC_LARGE, info=0
            codes[nc + 1] = (unsigned char)pr.alloc_offset;
            codes[nc + 2] = (unsigned char)((pr.alloc_size / 8) & 0xFF);
            codes[nc + 3] = (unsigned char)((pr.alloc_size / 8) >> 8);
            nc += 4;
        } else {
            return 0;
        }
    }
    for (nocrt_size i = pr.push_count; i-- > 0;) {
        codes[nc] = (unsigned char)(pr.push_regs[i] << 4 | 0);  // op=PUSH_NONVOL
        codes[nc + 1] = (unsigned char)pr.push_offsets[i];
        nc += 2;
    }
    const nocrt_size ncodes = nc / 2;
    out[0] = 1;                                   // version 1, flags 0
    out[1] = (unsigned char)pr.stolen;            // SizeOfProlog
    out[2] = (unsigned char)ncodes;
    out[3] = 0;                                   // no frame register
    for (nocrt_size i = 0; i < nc; ++i) out[4 + i] = codes[i];
    nocrt_size total = 4 + nc;
    while (total % 4) out[total++] = 0;
    return total;
}

} // namespace hook_detail

inline bool hook_install(nocrt_hook& h, unsigned char* target, void* detour) {
    h = {};
    const nocrt_prologue pr = probe_prologue(target, 5);
    if (!pr.ok) return false;  // refusal is logged by the consumer via pr.reason
    unsigned char* region = hook_detail::ensure_region(target);
    if (!region || hook_detail::g_region_used + kHookSlotSize > kHookRegionSize) return false;
    unsigned char* slot = region + hook_detail::g_region_used;
    hook_detail::g_region_used += kHookSlotSize;

    const bool was_rx = hook_detail::g_region_rx;
    const auto vp = (hook_detail::VirtualProtect_t)NOCRT_FN_RAW("VirtualProtect");
    unsigned long old = 0;
    if (was_rx && vp) vp(region, kHookRegionSize, 0x04, &old);

    for (nocrt_size i = 0; i < 16; ++i) h.saved[i] = target[i];
    for (nocrt_size i = 0; i < pr.stolen; ++i) slot[i] = target[i];
    unsigned char* jump = slot + pr.stolen;
    jump[0] = 0x48;
    jump[1] = 0xB8;
    memcpy(jump + 2, &detour, 8);
    jump[10] = 0xFF;
    jump[11] = 0xE0;
    const nocrt_size ulen = hook_detail::build_unwind(slot + 32, pr);
    if (!ulen) return false;
    unsigned char* rf = slot + 48;  // RUNTIME_FUNCTION: 3 x u32
    const unsigned long slot_off = (unsigned long)(slot - region);
    *(unsigned long*)(rf + 0) = slot_off;
    *(unsigned long*)(rf + 4) = slot_off + (unsigned long)(pr.stolen + 12);
    *(unsigned long*)(rf + 8) = (unsigned long)((slot + 32) - region);
    const auto raft = (unsigned char*(__stdcall*)(void*, unsigned long, unsigned long long))
        NOCRT_FN("RtlAddFunctionTable");
    if (raft) {
        if (!raft(rf, 1, (unsigned long long)region)) return false;
        h.unwind_table = rf;
    }
    if (!was_rx && vp) {
        vp(region, kHookRegionSize, 0x20, &old);
        hook_detail::g_region_rx = true;
    } else if (was_rx && vp) {
        vp(region, kHookRegionSize, 0x20, &old);
    }

    void* threads[64];
    const nocrt_size nt = hook_detail::suspend_others(threads, 64);
    if (vp) vp(target, pr.stolen, 0x40, &old);
    target[0] = 0xE9;
    const int d = (int)(long long)(slot - (target + 5));
    memcpy(target + 1, &d, 4);
    h.expect[0] = 0xE9;
    memcpy(h.expect + 1, &d, 4);
    if (vp) vp(target, pr.stolen, old, &old);
    hook_detail::fixup_threads(threads, nt, target, slot);
    hook_detail::resume_all(threads, nt);
    const auto fic = (hook_detail::FlushIC_t)NOCRT_FN("FlushInstructionCache");
    if (fic) fic((void*)(long long)-1, nullptr, 0);
    h.target = target;
    h.slot = slot;
    h.stolen = pr.stolen;
    h.active = true;
    return true;
}

// Sound verification: exact patch bytes, not "starts with E9". A foreign
// re-hook or a repointed displacement fails this.
inline bool hook_verify(const nocrt_hook& h) {
    if (!h.active) return false;
    for (nocrt_size i = 0; i < 5; ++i) {
        if (h.target[i] != h.expect[i]) return false;
    }
    return true;
}

inline bool hook_remove(nocrt_hook& h) {
    if (!h.active) return false;
    const auto vp = (hook_detail::VirtualProtect_t)NOCRT_FN_RAW("VirtualProtect");
    unsigned long old = 0;
    void* threads[64];
    const nocrt_size nt = hook_detail::suspend_others(threads, 64);
    if (vp) vp(h.target, h.stolen, 0x40, &old);
    for (nocrt_size i = 0; i < 5; ++i) h.target[i] = h.saved[i];
    if (vp) vp(h.target, h.stolen, old, &old);
    hook_detail::resume_all(threads, nt);
    const auto fic = (hook_detail::FlushIC_t)NOCRT_FN("FlushInstructionCache");
    if (fic) fic((void*)(long long)-1, nullptr, 0);
    if (h.unwind_table) {
        const auto rdft = (int(__stdcall*)(void*))NOCRT_FN("RtlDeleteFunctionTable");
        if (rdft) rdft(h.unwind_table);
    }
    h.active = false;
    return true;
}

} // namespace nocrt
