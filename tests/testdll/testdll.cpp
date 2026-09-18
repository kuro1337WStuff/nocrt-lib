#include "nocrt/nocrt.h"
#include "nocrt/dll.h"
#include "nocrt/secstr.h"
#include "nocrt/xstr.h"
#include "nocrt/lazy.h"
#include "nocrt/hostcrt.h"
#include "nocrt/pattern.h"
#include "nocrt/hook.h"
#include "nocrt/thread.h"
#include "nocrt/stack.h"
#include "nocrt/trace.h"

// Zero-import test DLL. Every stage writes a numeric trace record into the
// in-image ring (trace.h); the injector reads it back with --dump-log, so a
// silent failure names its stage instead of guessing.

enum stage : unsigned long {
    kStEntry = 1,
    kStCaps = 2,
    kStFirstOut = 3,
    kStSpawn = 4,
    kStWorker = 5,
    kStHostCrt = 6,
    kStHookScan = 7,
    kStHookInstall = 8,
    kStDone = 9,
};

extern "C" long long detour_target(long long) { return 1337; }

// imul rax, rcx, 0x1234567 - the host_target prologue marker.
constexpr nocrt::pattern kHostFn("48 69 C1 67 45 23 01");

static unsigned long __stdcall worker(void*) {
    NOCRT_TR(kStWorker, 0, 0);
    constexpr auto s1 = NOCRT_SECSTR("[nocrt] injected: strings alive");
    {
        nocrt::secview v(s1);
        nocrt::out(v.c_str());
        nocrt::say("\r\n");
    }
    using puts_t = int(__cdecl*)(const char*);
    const puts_t ps = (puts_t)NOCRT_HOST_FN("ucrtbase.dll", "puts");
    constexpr auto s2 = NOCRT_SECSTR("[nocrt] host crt says: hi");
    {
        nocrt::secview v(s2);
        if (ps) {
            ps(v.c_str());
            NOCRT_TR(kStHostCrt, 1, 0);
        } else {
            NOCRT_TR(kStHostCrt, 0, 0);
        }
    }
    const unsigned char* host = nocrt::module_base(0);
    const unsigned long hsz = nocrt::module_size(host);
    const unsigned char* hit = nocrt::scan(host, hsz, kHostFn);
    const bool uniq = hit != nullptr &&
                      nocrt::count_matches(host, hsz, kHostFn.b, kHostFn.n) == 1;
    NOCRT_TR(kStHookScan, uniq ? 1 : 0, (unsigned long)(unsigned long long)hit);
    if (uniq) {
        nocrt::nocrt_hook h = {};
        const bool ok = nocrt::hook_install(h, (unsigned char*)hit, (void*)&detour_target);
        NOCRT_TR(kStHookInstall, ok ? 1 : 0, (unsigned long)h.stolen);
        if (ok) nocrt::say("[nocrt] inline hook installed\r\n");
    }
    NOCRT_TR(kStDone, 0, 0);
    return 0;
}

extern "C" int nocrt_dll_main(nocrt_dword reason) {
    if (reason != kDllProcessAttach) return 1;
    nocrt::trace_init(nocrt::g_config ? nocrt::g_config->image_base : 0, 0);
    NOCRT_TR(kStEntry, reason, 0);
    const nocrt::nocrt_caps caps = nocrt::probe_caps();
    const bool unwind_ok =
        nocrt::g_config ? nocrt::register_own_unwind(nocrt::g_config->image_base) : false;
    NOCRT_TR(kStCaps,
             caps.cet_cpu | (caps.cet_ss_cpu << 1) | (caps.shadow_policy << 2) |
                 (caps.ssp_live << 3),
             unwind_ok ? 1 : 0);
    const bool first = nocrt::say("[nocrt] entry\r\n");
    NOCRT_TR(kStFirstOut, first ? 1 : 0, 0);
    void* thread = nullptr;
    const bool sp = nocrt::spawn(&worker, nullptr, &thread);
    NOCRT_TR(kStSpawn, sp ? 1 : 0, 0);
    return sp ? 0 : 1;  // 0 = success: thread exit code 0 must mean success
}
