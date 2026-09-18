#pragma once

#include "nocrt/nocrt.h"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

// Lazy import resolution: no static imports at all.
//
// Walks PEB -> LDR module list, parses each module's export directory, and
// matches function names by a compile-time-computed hash. Because the hash is
// seeded per expansion site (line-derived), the immediates baked into the
// image differ across sites and builds - unlike stock lazy-importer headers
// whose fixed hash constants are themselves a stable signature.
//
// x64 Windows only. Offsets below are the long-stable PEB/LDR layout.

namespace nocrt {

constexpr unsigned long long kLazySalt = 0x9E3779B97F4A7C15ull;

constexpr unsigned long long line_seed(unsigned long long line) {
    return xmix(line * 0x1000003B9ull ^ kLazySalt);
}

// FNV-1a style name hash, seeded. Identical at compile time and runtime.
constexpr unsigned long long str_hash(const char* s, unsigned long long seed) {
    unsigned long long h = seed ^ 0xCBF29CE484222325ull;
    for (nocrt_size i = 0; s[i]; ++i) {
        h ^= (unsigned char)s[i];
        h *= 0x100000001B3ull;
    }
    return h;
}

namespace lazy_detail {

constexpr unsigned long long kPebTebOffset = 0x60;
constexpr unsigned long long kPebLdr = 0x18;
constexpr unsigned long long kLdrInMemoryOrder = 0x20;
// Offsets relative to the InMemoryOrderLinks member we traverse from.
constexpr unsigned long long kEntryDllBase = 0x20;
constexpr unsigned long long kEntryBaseName = 0x48;
constexpr unsigned long long kUnicodeBuffer = 0x08;

inline const unsigned char* peb() {
#if defined(_MSC_VER)
    return (const unsigned char*)__readgsqword(kPebTebOffset);
#else
    return nullptr;
#endif
}

inline unsigned long long rd64le(const unsigned char* p) { return rd64(p); }
inline unsigned long rd32le(const unsigned char* p) { return rd32(p); }
inline unsigned short rd16le(const unsigned char* p) { return rd16(p); }

// Hash an export name at runtime with the same algorithm/seed as str_hash.
inline unsigned long long hash_name(const char* s, unsigned long long seed) {
    unsigned long long h = seed ^ 0xCBF29CE484222325ull;
    for (nocrt_size i = 0; s[i]; ++i) {
        h ^= (unsigned char)s[i];
        h *= 0x100000001B3ull;
    }
    return h;
}

inline const unsigned char* find_export(const unsigned char* base,
                                        unsigned long long want,
                                        unsigned long long seed) {
    if (base[0] != 'M' || base[1] != 'Z') return nullptr;
    const unsigned long lfanew = rd32le(base + 0x3C);
    const unsigned char* nt = base + lfanew;
    if (rd32le(nt) != 0x4550) return nullptr;
    const unsigned char* opt = nt + 24;
    const unsigned short magic = rd16le(opt);
    const unsigned char* datadir = opt + ((magic == 0x20B) ? 112 : 96);
    const unsigned long exp_rva = rd32le(datadir);
    const unsigned long exp_size = rd32le(datadir + 4);
    if (!exp_rva) return nullptr;
    const unsigned char* exp = base + exp_rva;
    const unsigned long num_names = rd32le(exp + 24);
    const unsigned long addr_funcs = rd32le(exp + 28);
    const unsigned long addr_names = rd32le(exp + 32);
    const unsigned long addr_ords = rd32le(exp + 36);
    if (!num_names || !addr_funcs || !addr_names || !addr_ords) return nullptr;
    for (unsigned long i = 0; i < num_names; ++i) {
        const char* name = (const char*)(base + rd32le(base + addr_names + i * 4));
        if (hash_name(name, seed) != want) continue;
        const unsigned short ord = rd16le(base + addr_ords + i * 2);
        const unsigned long func_rva = rd32le(base + addr_funcs + (unsigned long)ord * 4);
        // Forwarded exports point back inside the export directory.
        if (func_rva >= exp_rva && func_rva < exp_rva + exp_size) return nullptr;
        return base + func_rva;
    }
    return nullptr;
}

} // namespace lazy_detail

// Resolve a function by hashed name across all loaded modules.
inline void* lazy_resolve(unsigned long long want, unsigned long long seed) {
    const unsigned char* p = lazy_detail::peb();
    if (!p) return nullptr;
    const unsigned char* ldr = *(const unsigned char**)(p + lazy_detail::kPebLdr);
    if (!ldr) return nullptr;
    const unsigned char* head = ldr + lazy_detail::kLdrInMemoryOrder;
    const unsigned char* cur = *(const unsigned char**)(head);
    while (cur && cur != head) {
        const unsigned char* dll_base = *(const unsigned char**)(cur + lazy_detail::kEntryDllBase);
        if (dll_base) {
            const unsigned char* hit = lazy_detail::find_export(dll_base, want, seed);
            if (hit) return (void*)hit;
        }
        cur = *(const unsigned char**)(cur);
    }
    return nullptr;
}

template <unsigned long long H, unsigned long long Seed>
inline void* lazy_fn() {
    return lazy_resolve(H, Seed);
}

} // namespace nocrt

// Per-expansion-site seeded lookup. The seed is line-derived so identical
// literals at different sites produce different immediates in the image.
#define NOCRT_FN(lit)                                                                          \
    ::nocrt::lazy_fn<::nocrt::str_hash(lit, ::nocrt::line_seed(__LINE__)),                     \
                     ::nocrt::line_seed(__LINE__)>()
