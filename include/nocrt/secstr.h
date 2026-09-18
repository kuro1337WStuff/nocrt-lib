#pragma once

#include "nocrt/nocrt.h"

// Hardened compile-time strings: per-string distinct decrypt CODE.
//
// xstr proves a single shared decrypt routine is the weak point - reverse it
// once and every string falls. secstr fixes that: each string carries its own
// 5-step operation program (op codes + keys) packed into a template parameter,
// derived from the expansion-site seed. Encryption is constexpr; decryption is
// a template-unrolled inverse chain, so every string compiles to its OWN
// straight-line operation sequence with its OWN constants. There is no single
// decrypt function to reverse.
//
// Program encoding (55 bits of a u64): per step s, bits [s*11, s*11+2] = op
// code, bits [s*11+3, s*11+10] = key byte.

namespace nocrt {

constexpr nocrt_size kSecSteps = 5;

constexpr unsigned char rol8(unsigned char c, unsigned r) {
    r &= 7;
    return (unsigned char)((c << r) | (c >> ((8 - r) & 7)));
}
constexpr unsigned char ror8(unsigned char c, unsigned r) {
    r &= 7;
    return (unsigned char)((c >> r) | (c << ((8 - r) & 7)));
}

// Pack a per-site seed into a 5-step operation program.
constexpr unsigned long long sec_prog(unsigned long long seed) {
    unsigned long long p = 0;
    for (nocrt_size s = 0; s < kSecSteps; ++s) {
        const unsigned long long r = xmix(seed ^ (s * 0xC2B2AE3D27D4EB4Full));
        const unsigned long long code = (r & 7) % 6;
        const unsigned long long key = (r >> 11) & 0xFF;
        p |= code << (s * 11);
        p |= key << (s * 11 + 3);
    }
    return p;
}

template <unsigned long long P, nocrt_size S>
struct sec_op {
    static constexpr unsigned code() { return (unsigned)((P >> (S * 11)) & 7) % 6; }
    static constexpr unsigned char key() { return (unsigned char)((P >> (S * 11 + 3)) & 0xFF); }
};

// Position-dependent key byte: mixes the site seed, the byte index and the
// step, then folds in the program's per-step key constant.
template <unsigned long long P, nocrt_size S>
constexpr unsigned char sec_poskey(unsigned long long seed, nocrt_size i) {
    const unsigned char stream =
        (unsigned char)(xmix(seed + i * 0x9E3779B97F4A7C15ull + S * 0xC2B2AE3D27D4EB4Full) & 0xFF);
    return (unsigned char)(stream ^ sec_op<P, S>::key());
}

template <unsigned long long P, nocrt_size S>
constexpr unsigned char sec_enc_step(unsigned char c, unsigned char pk) {
    constexpr unsigned code = sec_op<P, S>::code();
    if constexpr (code == 0) return (unsigned char)(c ^ pk);
    else if constexpr (code == 1) return (unsigned char)(c + pk);
    else if constexpr (code == 2) return (unsigned char)(c - pk);
    else if constexpr (code == 3) return rol8(c, pk & 7);
    else if constexpr (code == 4) return ror8(c, pk & 7);
    else return (unsigned char)~c;
}

template <unsigned long long P, nocrt_size S>
constexpr unsigned char sec_dec_step(unsigned char c, unsigned char pk) {
    constexpr unsigned code = sec_op<P, S>::code();
    if constexpr (code == 0) return (unsigned char)(c ^ pk);
    else if constexpr (code == 1) return (unsigned char)(c - pk);
    else if constexpr (code == 2) return (unsigned char)(c + pk);
    else if constexpr (code == 3) return ror8(c, pk & 7);
    else if constexpr (code == 4) return rol8(c, pk & 7);
    else return (unsigned char)~c;
}

template <unsigned long long P>
constexpr unsigned char sec_enc(unsigned char c, nocrt_size i, unsigned long long seed) {
    c = sec_enc_step<P, 0>(c, sec_poskey<P, 0>(seed, i));
    c = sec_enc_step<P, 1>(c, sec_poskey<P, 1>(seed, i));
    c = sec_enc_step<P, 2>(c, sec_poskey<P, 2>(seed, i));
    c = sec_enc_step<P, 3>(c, sec_poskey<P, 3>(seed, i));
    c = sec_enc_step<P, 4>(c, sec_poskey<P, 4>(seed, i));
    return c;
}

// Inverse chain, applied in reverse step order. Unrolled per instantiation:
// this is the per-string distinct decrypt code.
template <unsigned long long P>
inline unsigned char sec_dec(unsigned char c, nocrt_size i, unsigned long long seed) {
    c = sec_dec_step<P, 4>(c, sec_poskey<P, 4>(seed, i));
    c = sec_dec_step<P, 3>(c, sec_poskey<P, 3>(seed, i));
    c = sec_dec_step<P, 2>(c, sec_poskey<P, 2>(seed, i));
    c = sec_dec_step<P, 1>(c, sec_poskey<P, 1>(seed, i));
    c = sec_dec_step<P, 0>(c, sec_poskey<P, 0>(seed, i));
    return c;
}

template <nocrt_size N, unsigned long long P, unsigned long long Seed>
class secstr;

// Scoped on-the-fly decryptor: plaintext lives only in this stack buffer and
// is zeroed on destruction.
template <nocrt_size N, unsigned long long P, unsigned long long Seed>
class secview {
    char buf[N];

public:
    explicit secview(const secstr<N, P, Seed>& s) : buf{} {
        for (nocrt_size i = 0; i < N; ++i) buf[i] = (char)sec_dec<P>(s.at(i), i, Seed);
    }
    ~secview() { memset(buf, 0, N); }
    const char* c_str() const { return buf; }
    constexpr nocrt_size size() const { return N; }
};

template <nocrt_size N, unsigned long long P, unsigned long long Seed>
class secstr {
    unsigned char enc[N];

public:
    constexpr secstr(const char (&lit)[N]) : enc{} {
        for (nocrt_size i = 0; i < N; ++i) enc[i] = sec_enc<P>((unsigned char)lit[i], i, Seed);
    }
    constexpr unsigned char at(nocrt_size i) const { return enc[i]; }
    constexpr const unsigned char* data() const { return enc; }
    constexpr nocrt_size size() const { return N; }
};

// Address of this string's decrypt code, for self-tests that prove two
// strings do not share a decrypt routine.
template <nocrt_size N, unsigned long long P, unsigned long long Seed>
inline const unsigned char* sec_code(const secstr<N, P, Seed>&) {
    return (const unsigned char*)(const void*)&sec_dec<P>;
}

} // namespace nocrt

#define NOCRT_SECSTR(lit)                                                                      \
    ::nocrt::secstr<sizeof(lit), ::nocrt::sec_prog(::nocrt::line_seed(__LINE__)),              \
                    ::nocrt::line_seed(__LINE__)>(lit)
