#pragma once

#include "nocrt/nocrt.h"

// Compile-time polymorphic XOR strings.
//
// NOCRT_XSTR("literal") encrypts the literal DURING COMPILATION with a key
// stream derived from a per-expansion seed (__LINE__ + __COUNTER__), so two
// expansions of the same literal produce different ciphertext in the image.
// The plaintext never appears in the binary; decryption happens at runtime
// into a stack buffer that is zeroed when it goes out of scope.

namespace nocrt {

// murmur-style finalizer mix; constexpr so encryption is a compile-time act.
constexpr unsigned long long xmix(unsigned long long s) {
    s ^= s >> 33;
    s *= 0xFF51AFD7ED558CCDull;
    s ^= s >> 33;
    s *= 0xC4CEB9FE1A85EC53ull;
    s ^= s >> 33;
    return s;
}

constexpr unsigned char xkey_byte(unsigned long long seed, nocrt_size i) {
    return (unsigned char)(xmix(seed + i * 0x9E3779B97F4A7C15ull) & 0xFF);
}

// Per-instantiation seed. line+counter make every macro expansion unique,
// which is what makes the encryption polymorphic across use sites.
constexpr unsigned long long xseed(unsigned long long line, unsigned long long counter) {
    return xmix((line * 0x1000003B9ull) ^ (counter * 0x7F4A7C15ull) ^ 0xA5A5A5A5C3C3C3C3ull);
}

template <nocrt_size N, unsigned long long Seed>
struct xstr {
    char data[N];
    constexpr xstr(const char (&lit)[N]) : data{} {
        for (nocrt_size i = 0; i < N; ++i) {
            data[i] = (char)((unsigned char)lit[i] ^ xkey_byte(Seed, i));
        }
    }
    constexpr nocrt_size size() const { return N; }
};

// Runtime decryptor. Plaintext exists only in this stack buffer.
template <nocrt_size N, unsigned long long Seed>
class xdec {
    char buf[N];

public:
    explicit xdec(const xstr<N, Seed>& s) : buf{} {
        for (nocrt_size i = 0; i < N; ++i) {
            buf[i] = (char)((unsigned char)s.data[i] ^ xkey_byte(Seed, i));
        }
    }
    ~xdec() { memset(buf, 0, N); }
    const char* c_str() const { return buf; }
    constexpr nocrt_size size() const { return N; }
};

// FNV-1a, used to demonstrate that two encryptions of one literal differ.
constexpr unsigned long long fnv1a(const char* p, nocrt_size n) {
    unsigned long long h = 0xCBF29CE484222325ull;
    for (nocrt_size i = 0; i < n; ++i) {
        h ^= (unsigned char)p[i];
        h *= 0x100000001B3ull;
    }
    return h;
}

} // namespace nocrt

#define NOCRT_XSTR(lit) ::nocrt::xstr<sizeof(lit), ::nocrt::xseed(__LINE__, __COUNTER__)>(lit)
