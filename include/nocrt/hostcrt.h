#pragma once

#include "nocrt/lazy.h"
#include "nocrt/pattern.h"

// Host-CRT reachability: a zero-import DLL mapped into a CRT-bearing host can
// locate the host's CRT modules in the PEB and resolve their exports by hash,
// then call host standard-library functions with decrypted strings. Nothing
// here is imported; everything is walked at runtime.

namespace nocrt {

constexpr unsigned long long kHostCrtSeed = 0x5A5AC3C3A5A53C3Cull;

// Case-insensitive hash of a module's UTF-16 base name, matching str_hash over
// the lowered ASCII form (seed 0 on both sides).
inline unsigned long long hash_wname(const unsigned short* w, unsigned long long seed) {
    unsigned long long h = seed ^ 0xCBF29CE484222325ull;
    for (nocrt_size i = 0; w[i]; ++i) {
        unsigned char c = (unsigned char)(w[i] & 0xFF);
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
        h ^= c;
        h *= 0x100000001B3ull;
    }
    return h;
}

inline const unsigned char* module_by_name_hash(unsigned long long want) {
    const unsigned char* p = lazy_detail::peb();
    if (!p) return nullptr;
    const unsigned char* ldr = *(const unsigned char**)(p + lazy_detail::kPebLdr);
    if (!ldr) return nullptr;
    const unsigned char* head = ldr + lazy_detail::kLdrInMemoryOrder;
    const unsigned char* cur = *(const unsigned char**)(head);
    while (cur && cur != head) {
        const unsigned char* dll_base = *(const unsigned char**)(cur + lazy_detail::kEntryDllBase);
        const unsigned char* name =
            *(const unsigned char**)(cur + lazy_detail::kEntryBaseName + lazy_detail::kUnicodeBuffer);
        if (dll_base && name && hash_wname((const unsigned short*)name, 0) == want) {
            return dll_base;
        }
        cur = *(const unsigned char**)(cur);
    }
    return nullptr;
}

// Resolve a function inside a named loaded module (host CRT included).
inline void* host_resolve(unsigned long long mod_hash, unsigned long long fn_hash) {
    const unsigned char* base = module_by_name_hash(mod_hash);
    if (!base) return nullptr;
    return (void*)lazy_detail::find_export(base, fn_hash, kHostCrtSeed);
}

// Cross-check: derive a byte pattern from a resolved address and confirm a
// pattern scan over [base, base+size) lands exactly on that address. CRT code
// is often duplicated (aliases, folded prologues), so the signature grows
// until it is unique; agreement between the export walker and the scanner at
// a unique signature is the proof.
inline bool cross_check(const unsigned char* base, nocrt_size size, const unsigned char* addr,
                        nocrt_size len) {
    if (!addr || addr < base || addr + len > base + size) return false;
    for (nocrt_size L = len; L <= 64; L += 8) {
        if (addr + L > base + size) break;
        pattern_byte sig[64];
        for (nocrt_size i = 0; i < L; ++i) {
            sig[i].value = addr[i];
            sig[i].any = false;
        }
        if (count_matches(base, size, sig, L) != 1) continue;
        return scan(base, size, sig, L) == addr;
    }
    return false;
}

} // namespace nocrt

// Template parameters force the name hashes to fold at compile time, so the
// module/function name literals never materialize in .rdata (a runtime
// str_hash over a literal would emit the plaintext).
template <unsigned long long MH, unsigned long long FH>
inline void* nocrt_host_fn() {
    return ::nocrt::host_resolve(MH, FH);
}

// Resolve a host-module function by name at runtime, no imports, no plaintext.
#define NOCRT_HOST_FN(mod_lit, fn_lit)                                                         \
    ::nocrt_host_fn<::nocrt::str_hash(mod_lit, 0),                                             \
                    ::nocrt::str_hash(fn_lit, ::nocrt::kHostCrtSeed)>()
