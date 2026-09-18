#pragma once

#include "nocrt/nocrt.h"

// Runtime pattern scanning with compile-time pattern parsing.
//
// Patterns use IDA-style syntax: "48 8B 05 ? ? ? ? 48 85 C0". Because the
// parser is constexpr, the compiled pattern (bytes + mask) is baked into
// .rdata and no parsing happens at runtime.

namespace nocrt {

struct pattern_byte {
    unsigned char value;
    bool any;
};

constexpr unsigned char hexval(char c) {
    return (c >= '0' && c <= '9')   ? (unsigned char)(c - '0')
         : (c >= 'a' && c <= 'f')   ? (unsigned char)(c - 'a' + 10)
         : (c >= 'A' && c <= 'F')   ? (unsigned char)(c - 'A' + 10)
                                    : (unsigned char)0;
}

template <nocrt_size N>
struct pattern {
    pattern_byte b[N];
    nocrt_size n;

    constexpr pattern(const char (&s)[N]) : b{}, n(0) {
        nocrt_size i = 0;
        while (i < N) {
            const char c = s[i];
            if (c == 0) break;
            if (c == ' ') { ++i; continue; }
            if (c == '?') {
                b[n].any = true;
                b[n].value = 0;
                ++n;
                ++i;
                if (i < N && s[i] == '?') ++i;
                continue;
            }
            const unsigned char hi = hexval(c);
            const unsigned char lo = (i + 1 < N) ? hexval(s[i + 1]) : (unsigned char)0;
            b[n].value = (unsigned char)((hi << 4) | lo);
            b[n].any = false;
            ++n;
            i += 2;
        }
    }
};

// Scan [base, base+size) for the first match. Wildcard bytes match anything.
inline const unsigned char* scan(const unsigned char* base, nocrt_size size,
                                 const pattern_byte* pat, nocrt_size pn) {
    if (pn == 0 || size < pn) return nullptr;
    const nocrt_size last = size - pn;
    for (nocrt_size i = 0; i <= last; ++i) {
        bool ok = true;
        for (nocrt_size j = 0; j < pn; ++j) {
            if (!pat[j].any && base[i + j] != pat[j].value) { ok = false; break; }
        }
        if (ok) return base + i;
    }
    return nullptr;
}

template <nocrt_size N>
inline const unsigned char* scan(const unsigned char* base, nocrt_size size, const pattern<N>& p) {
    return scan(base, size, p.b, p.n);
}

inline nocrt_size count_matches(const unsigned char* base, nocrt_size size,
                                const pattern_byte* pat, nocrt_size pn) {
    nocrt_size hits = 0;
    if (pn == 0 || size < pn) return 0;
    const nocrt_size last = size - pn;
    for (nocrt_size i = 0; i <= last; ++i) {
        bool ok = true;
        for (nocrt_size j = 0; j < pn; ++j) {
            if (!pat[j].any && base[i + j] != pat[j].value) { ok = false; break; }
        }
        if (ok) ++hits;
    }
    return hits;
}

// Runtime-built pattern scan (used when a signature is generated on the fly).
inline const unsigned char* scan_masked(const unsigned char* base, nocrt_size size,
                                        const unsigned char* values, const bool* mask,
                                        nocrt_size pn) {
    if (pn == 0 || size < pn) return nullptr;
    const nocrt_size last = size - pn;
    for (nocrt_size i = 0; i <= last; ++i) {
        bool ok = true;
        for (nocrt_size j = 0; j < pn; ++j) {
            if (!mask[j] && base[i + j] != values[j]) { ok = false; break; }
        }
        if (ok) return base + i;
    }
    return nullptr;
}

// Resolve a RIP-relative target: `at` points at the instruction, `imm_off` is
// the offset of the rel32 within it, `insn_len` its total length.
inline const unsigned char* rel32(const unsigned char* at, nocrt_size imm_off, nocrt_size insn_len) {
    int disp = 0;
    memcpy(&disp, at + imm_off, sizeof(disp));
    return at + insn_len + disp;
}

} // namespace nocrt
