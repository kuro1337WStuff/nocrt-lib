#include "nocrt/nocrt.h"
#include "nocrt/dll.h"
#include "nocrt/secstr.h"
#include "nocrt/lazy.h"
#include "nocrt/hostcrt.h"
#include "nocrt/pattern.h"
#include "nocrt/hook.h"
#include "nocrt/thread.h"
#include "nocrt/stack.h"

// Zero-import test DLL. Everything below runs inside the host process with no
// imports: strings decrypt on the fly, host CRT functions are resolved by
// export hash, the host's own code is located by pattern and hooked, and the
// stack is walked to report unbacked frames.

static void print_dec(unsigned long long v) {
    char buf[24];
    nocrt_size n = 0;
    if (v == 0) {
        nocrt::out("0", 1);
        return;
    }
    while (v) {
        buf[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    char rev[24];
    for (nocrt_size i = 0; i < n; ++i) rev[i] = buf[n - 1 - i];
    nocrt::out(rev, n);
}

static void print_hex(unsigned long long v) {
    const char digits[] = "0123456789abcdef";
    char buf[16];
    for (int i = 0; i < 16; ++i) buf[i] = digits[(v >> ((15 - i) * 4)) & 0xF];
    nocrt::out(buf, 16);
}

extern "C" long long detour_target(long long) { return 1337; }

// imul rax, rcx, 0x1234567 - the host_target body marker.
constexpr nocrt::pattern kHostFn("48 69 C1 67 45 23 01");

static unsigned long __stdcall worker(void*) {
    constexpr auto s1 = NOCRT_SECSTR("[nocrt] injected: strings alive");
    constexpr auto s2 = NOCRT_SECSTR("[nocrt] host crt says: ");
    {
        nocrt::secview v(s1);
        nocrt::out(v.c_str());
        nocrt::out("\r\n", 2);
    }

    // Strings on the lazy importer: decrypt on the fly, hand to a host CRT
    // function resolved purely by export hash. Modern CRT hosts load ucrtbase
    // (which exports puts but not printf on this system), so try both.
    using printf_t = int(__cdecl*)(const char*, ...);
    using puts_t = int(__cdecl*)(const char*);
    printf_t pf = (printf_t)NOCRT_HOST_FN("msvcrt.dll", "printf");
    puts_t ps = (puts_t)NOCRT_HOST_FN("ucrtbase.dll", "puts");
    {
        nocrt::secview v(s2);
        if (pf) {
            pf("%s hello from host printf\r\n", v.c_str());
        } else if (ps) {
            ps(v.c_str());
        } else {
            nocrt::out(v.c_str());
            nocrt::out("no host crt print fn\r\n", 22);
        }
    }

    // Locate host_target by pattern in the host image and hook it.
    const unsigned char* host = nocrt::module_base(0);
    const unsigned long hsz = nocrt::module_size(host);
    const unsigned char* hit = nocrt::scan(host, hsz, kHostFn);
    if (hit && nocrt::count_matches(host, hsz, kHostFn.b, kHostFn.n) == 1) {
        // Prologue probe decides the stolen length; RIP-relative or branch
        // forms are refused outright.
        nocrt::nocrt_hook h = {};
        const bool ok = nocrt::hook_install(h, (unsigned char*)hit, (void*)&detour_target);
        nocrt::out("[dbg] stolen: ", 12);
        print_hex(h.stolen);
        nocrt::out("\r\n", 2);
        nocrt::out("[dbg] hit: ", 10);
        print_hex((unsigned long long)hit);
        nocrt::out(" tramp: ", 8);
        print_hex((unsigned long long)h.slot);
        nocrt::out(" ok: ", 5);
        print_hex(ok ? 1 : 0);
        nocrt::out("\r\n", 2);
        if (ok) {
            nocrt::out("[nocrt] inline hook installed\r\n", 31);
        } else {
            nocrt::out("[nocrt] hook install failed\r\n", 29);
        }
    } else {
        nocrt::out("[nocrt] host pattern not found/unique\r\n", 39);
    }

    // Stackwalk report: unbacked frames are the injection tell.
    unsigned long long frames[32];
    const nocrt_size n = nocrt::walk_frames(frames, 32);
    const nocrt_size unbacked = nocrt::count_unbacked_frames(frames, n);
    nocrt::out("[nocrt] frames: ", 16);
    print_dec(n);
    nocrt::out(" unbacked: ", 11);
    print_dec(unbacked);
    nocrt::out("\r\n", 2);

    return 0;
}

extern "C" int nocrt_dll_main(nocrt_dword reason) {
    if (reason != kDllProcessAttach) return 1;
    const nocrt::nocrt_caps caps = nocrt::probe_caps();
    const bool unwind_ok =
        nocrt::g_config ? nocrt::register_own_unwind(nocrt::g_config->image_base) : false;
    nocrt::out("[dbg] caps cet=", 15);
    print_hex(caps.cet_cpu);
    nocrt::out(" ss=", 5);
    print_hex(caps.cet_ss_cpu);
    nocrt::out(" pol=", 6);
    print_hex(caps.shadow_policy);
    nocrt::out(" ssp=", 6);
    print_hex(caps.ssp_live);
    nocrt::out(" unwind=", 9);
    print_hex(unwind_ok ? 1 : 0);
    nocrt::out("\r\n", 2);
    // Side channel independent of host stdout: proves whether the remote
    // thread executes at all.
    {
        using CreateFileA_t = void*(__stdcall*)(const char*, unsigned long, unsigned long,
                                                void*, unsigned long, unsigned long, void*);
        using WriteFile_t = int(__stdcall*)(void*, const void*, unsigned long, unsigned long*,
                                            void*);
        auto cf = (CreateFileA_t)NOCRT_FN("CreateFileA");
        auto wf = (WriteFile_t)NOCRT_FN("WriteFile");
        if (cf && wf) {
            void* hf = cf("C:\\Users\\Loki\\nocrt\\build\\entry.log", 0x40000000, 0, nullptr, 2,
                          0, nullptr);
            if (hf != (void*)-1) {
                unsigned long w = 0;
                wf(hf, "entry-ran\n", 10, &w, nullptr);
                auto ch = (int(__stdcall*)(void*))NOCRT_FN("CloseHandle");
                if (ch) ch(hf);
            }
        }
    }
    void* tpc = NOCRT_FN("TrySubmitThreadpoolCallback");
    void* ct = NOCRT_FN("CreateThread");
    nocrt::out("[dbg] tpc: ", 10);
    print_hex((unsigned long long)tpc);
    nocrt::out(" ct: ", 6);
    print_hex((unsigned long long)ct);
    nocrt::out("\r\n", 2);
    void* thread = nullptr;
    if (!nocrt::spawn(&worker, nullptr, &thread)) return 0;
    return 1;
}
