#pragma once

#include "nocrt/nocrt.h"
#include "nocrt/lazy.h"

// Hook engine, three modes, each compile-time selectable so unused modes cost
// zero bytes:
//   NOCRT_HOOK_INLINE - inline detour + trampoline (process-wide, patches code)
//   NOCRT_HOOK_HWBP   - hardware breakpoint + VEH (zero code writes, per-thread,
//                       observation-only: detour cannot call the original)
//   NOCRT_HOOK_GUARD  - guard page + VEH (zero code writes, page granularity,
//                       one-shot until re-armed)
// v1 limitation, stated honestly: the inline trampoline copies patch_len bytes
// verbatim, so the patch length must cover whole instructions at the target.

#ifndef NOCRT_HOOK_INLINE
#define NOCRT_HOOK_INLINE 1
#endif
#ifndef NOCRT_HOOK_HWBP
#define NOCRT_HOOK_HWBP 1
#endif
#ifndef NOCRT_HOOK_GUARD
#define NOCRT_HOOK_GUARD 1
#endif

namespace nocrt {

using VirtualProtect_t = int(__stdcall*)(void*, nocrt_size, unsigned long, unsigned long*);
using VirtualAlloc_t = void*(__stdcall*)(void*, nocrt_size, unsigned long, unsigned long);

constexpr unsigned long kMemCommit = 0x1000;
constexpr unsigned long kMemReserve = 0x2000;
constexpr unsigned long kPageRw = 0x04;
constexpr unsigned long kPageRx = 0x20;
constexpr unsigned long kPageRwx = 0x40;

inline VirtualProtect_t virt_protect() {
    return (VirtualProtect_t)NOCRT_FN("VirtualProtect");
}

#if NOCRT_HOOK_INLINE
struct inline_hook {
    unsigned char* target;
    unsigned char* trampoline;
    unsigned char saved[16];
    nocrt_size patch_len;
    bool active;
};

inline bool hook_inline(inline_hook& h, unsigned char* target, void* detour) {
    const auto vp = virt_protect();
    const auto va = (VirtualAlloc_t)NOCRT_FN("VirtualAlloc");
    const auto vf = (int(__stdcall*)(void*, nocrt_size, unsigned long))NOCRT_FN("VirtualFree");
    if (!vp || !va) return false;
    const long long rel = (long long)((unsigned char*)detour - (target + 5));
    const bool use_rel32 = rel >= -2147483648LL && rel <= 2147483647LL;
    h.patch_len = use_rel32 ? 5 : 12;
    h.target = target;
    h.active = false;
    // The trampoline's jump-back is a rel32, so it must land within +/-2GB of
    // the target. Probe hints around the target until one sticks nearby.
    unsigned char* tramp = nullptr;
    unsigned char* page_target = (unsigned char*)((unsigned long long)target & ~0xFFFull);
    for (long long off = -0x70000000LL; off <= 0x70000000LL && !tramp; off += 0x00800000LL) {
        unsigned char* hint = page_target + off;
        if ((unsigned long long)hint < 0x10000) continue;
        unsigned char* p = (unsigned char*)va(hint, 64, kMemCommit | kMemReserve, kPageRw);
        if (!p) continue;
        const long long back_rel = (long long)((target + h.patch_len) - (p + h.patch_len + 5));
        if (back_rel < -2147483648LL || back_rel > 2147483647LL) {
            if (vf) vf(p, 0, 0x8000 /*MEM_RELEASE*/);
            continue;
        }
        tramp = p;
    }
    if (!tramp) return false;
    h.trampoline = tramp;
    for (nocrt_size i = 0; i < h.patch_len; ++i) h.saved[i] = target[i];
    for (nocrt_size i = 0; i < h.patch_len; ++i) h.trampoline[i] = h.saved[i];
    unsigned char* back = h.trampoline + h.patch_len;
    const long long rel2 = (long long)((target + h.patch_len) - (back + 5));
    if (rel2 < -2147483648LL || rel2 > 2147483647LL) return false;
    back[0] = 0xE9;
    const int d2 = (int)rel2;
    memcpy(back + 1, &d2, 4);
    unsigned long old = 0;
    vp(h.trampoline, 64, kPageRx, &old);
    vp(target, h.patch_len, kPageRw, &old);
    if (use_rel32) {
        target[0] = 0xE9;
        const int d = (int)rel;
        memcpy(target + 1, &d, 4);
    } else {
        target[0] = 0x48;
        target[1] = 0xB8;
        memcpy(target + 2, &detour, 8);
        target[10] = 0xFF;
        target[11] = 0xE0;
    }
    vp(target, h.patch_len, old, &old);
    h.active = true;
    return true;
}

inline bool unhook_inline(inline_hook& h) {
    if (!h.active) return false;
    const auto vp = virt_protect();
    if (!vp) return false;
    unsigned long old = 0;
    vp(h.target, h.patch_len, kPageRw, &old);
    for (nocrt_size i = 0; i < h.patch_len; ++i) h.target[i] = h.saved[i];
    vp(h.target, h.patch_len, old, &old);
    h.active = false;
    return true;
}

// Self-integrity: the patch at target is still exactly ours.
inline bool hook_verify(const inline_hook& h) {
    if (!h.active) return false;
    if (h.target[0] == 0xE9) return true;
    return h.target[0] == 0x48 && h.target[1] == 0xB8;
}
#endif

#if NOCRT_HOOK_HWBP || NOCRT_HOOK_GUARD
// x64 CONTEXT offsets we need.
constexpr nocrt_size kCtxDr0 = 0x48;
constexpr nocrt_size kCtxDr6 = 0x68;
constexpr nocrt_size kCtxDr7 = 0x70;
constexpr nocrt_size kCtxRip = 0xF8;
constexpr unsigned long kExcGuardPage = 0x80000001;
constexpr unsigned long kExcSingleStep = 0x80000004;

struct hwbp_hook {
    unsigned char* addr;
    void* detour;
    int slot;
    bool active;
};
struct guard_hook {
    unsigned char* page;
    unsigned char* addr;
    void* detour;
    unsigned long old_prot;
    bool active;
};

inline hwbp_hook g_hwbp[4];
inline guard_hook g_guard;
inline bool g_veh_installed;

inline long __stdcall nocrt_veh(void* epv) {
    unsigned char* er = *(unsigned char**)epv;
    unsigned char* ctx = *(unsigned char**)((unsigned char*)epv + 8);
    const unsigned long code = rd32(er);
    const unsigned long long rip = rd64(ctx + kCtxRip);
#if NOCRT_HOOK_HWBP
    if (code == kExcSingleStep) {
        for (int i = 0; i < 4; ++i) {
            if (g_hwbp[i].active && (unsigned char*)rip == g_hwbp[i].addr) {
                // Observation-only: redirect to detour and drop the breakpoint
                // so the detour runs once without re-triggering.
                *(unsigned long long*)(ctx + kCtxRip) = (unsigned long long)g_hwbp[i].detour;
                *(unsigned long long*)(ctx + kCtxDr0 + (nocrt_size)i * 8) = 0;
                unsigned long long dr7 = *(unsigned long long*)(ctx + kCtxDr7);
                dr7 &= ~(3ull << (i * 2));
                *(unsigned long long*)(ctx + kCtxDr7) = dr7;
                g_hwbp[i].active = false;
                return 0;
            }
        }
    }
#endif
#if NOCRT_HOOK_GUARD
    if (code == kExcGuardPage && g_guard.active && (unsigned char*)rip == g_guard.addr) {
        const auto vp = virt_protect();
        if (vp) {
            unsigned long old = 0;
            vp(g_guard.page, 0x1000, g_guard.old_prot, &old);
        }
        *(unsigned long long*)(ctx + kCtxRip) = (unsigned long long)g_guard.detour;
        g_guard.active = false;
        return 0;
    }
#endif
    (void)rip;
    return -1;
}

inline bool ensure_veh() {
    if (g_veh_installed) return true;
    const auto f = (void*(__stdcall*)(long(__stdcall*)(void*), unsigned long))NOCRT_FN(
        "AddVectoredExceptionHandler");
    if (!f) return false;
    if (!f(nocrt_veh, 1)) return false;
    g_veh_installed = true;
    return true;
}
#endif

#if NOCRT_HOOK_HWBP
// Per-thread install via debug registers. CONTEXT_DEBUG_REGISTERS = 0x00100000.
inline bool hwbp_install(void* thread, unsigned char* addr, void* detour, int slot) {
    if (slot < 0 || slot > 3 || !ensure_veh()) return false;
    const auto get_ctx = (int(__stdcall*)(void*, void*))NOCRT_FN("GetThreadContext");
    const auto set_ctx = (int(__stdcall*)(void*, void*))NOCRT_FN("SetThreadContext");
    if (!get_ctx || !set_ctx) return false;
    unsigned char ctx[0x4D0 + 16] = {};
    *(unsigned long*)(ctx + 0x30) = 0x00100000;
    if (!get_ctx(thread, ctx)) return false;
    *(unsigned long long*)(ctx + kCtxDr0 + (nocrt_size)slot * 8) = (unsigned long long)addr;
    unsigned long long dr7 = *(unsigned long long*)(ctx + kCtxDr7);
    dr7 |= (1ull << (slot * 2));
    *(unsigned long long*)(ctx + kCtxDr7) = dr7;
    if (!set_ctx(thread, ctx)) return false;
    g_hwbp[slot].addr = addr;
    g_hwbp[slot].detour = detour;
    g_hwbp[slot].slot = slot;
    g_hwbp[slot].active = true;
    return true;
}

inline bool hwbp_rearm(void* thread, int slot) {
    if (slot < 0 || slot > 3 || !g_hwbp[slot].addr) return false;
    return hwbp_install(thread, g_hwbp[slot].addr, g_hwbp[slot].detour, slot);
}
#endif

#if NOCRT_HOOK_GUARD
inline bool hook_guard(unsigned char* target, void* detour) {
    const auto vp = virt_protect();
    if (!vp || !ensure_veh()) return false;
    unsigned char* page = (unsigned char*)((unsigned long long)target & ~0xFFFull);
    unsigned long old = 0;
    if (!vp(page, 0x1000, 0x100 /*PAGE_GUARD*/ | kPageRx, &old)) return false;
    g_guard.page = page;
    g_guard.addr = target;
    g_guard.detour = detour;
    g_guard.old_prot = old;
    g_guard.active = true;
    return true;
}

inline bool guard_rearm() {
    if (!g_guard.addr) return false;
    return hook_guard(g_guard.addr, g_guard.detour);
}
#endif

} // namespace nocrt
