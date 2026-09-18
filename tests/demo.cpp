#include "nocrt/nocrt.h"
#include "nocrt/xstr.h"
#include "nocrt/secstr.h"

constexpr auto kSecA = NOCRT_SECSTR("hardened");
constexpr auto kSecB = NOCRT_SECSTR("hardened");

// Same literal at two expansion sites: compile-time polymorphic encryption
// must yield different ciphertext for each.
constexpr auto kWordA = NOCRT_XSTR("polymorphic");
constexpr auto kWordB = NOCRT_XSTR("polymorphic");

static void print_hex(unsigned long long v) {
    const char digits[] = "0123456789abcdef";
    char buf[16];
    for (int i = 0; i < 16; ++i) buf[i] = digits[(v >> ((15 - i) * 4)) & 0xF];
    nocrt::out(buf, 16);
}

extern "C" int nocrt_main() {
    const char banner[] = "nocrt: alive - no CRT linked\r\n";
    nocrt::out(banner, sizeof(banner) - 1);

    char buf[32];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "memcpy/memset/strlen work: ", 27);
    nocrt::out(buf, 27);

    const char* probe = "freestanding";
    char copy[16];
    memcpy(copy, probe, strlen(probe) + 1);
    if (!(strcmp(copy, "freestanding") == 0 && strncmp(copy, "free", 4) == 0 &&
          memcmp(copy, probe, 12) == 0 && memmove(copy + 1, copy, 12) != nullptr)) {
        nocrt::err("self-test failed\r\n", 18);
        return 1;
    }
    nocrt::out("ok\r\n", 4);

    nocrt::out("xstr cipher A fnv1a: ", 21);
    print_hex(nocrt::fnv1a(kWordA.data, kWordA.size()));
    nocrt::out("\r\n", 2);
    nocrt::out("xstr cipher B fnv1a: ", 21);
    print_hex(nocrt::fnv1a(kWordB.data, kWordB.size()));
    nocrt::out("\r\n", 2);

    if (nocrt::fnv1a(kWordA.data, kWordA.size()) == nocrt::fnv1a(kWordB.data, kWordB.size())) {
        // Must not contain the protected literal: an unwrapped error string
        // here would hand the secret to any analyst if DCE ever stops folding
        // this guard.
        nocrt::err("cipher collision\r\n", 18);
        return 1;
    }

    {
        nocrt::xdec da(kWordA);
        nocrt::xdec db(kWordB);
        if (strcmp(da.c_str(), db.c_str()) != 0 || strlen(da.c_str()) != 11) {
            nocrt::err("xstr decrypt failed\r\n", 21);
            return 1;
        }
        nocrt::out("xstr decrypt: ", 14);
        nocrt::out(da.c_str());
        nocrt::out("\r\n", 2);
    }

    // Hardened strings: same literal at two sites must produce different
    // ciphertext AND different decrypt machine code (no shared routine).
    nocrt::out("secstr code A: ", 15);
    print_hex((unsigned long long)(const void*)nocrt::sec_code(kSecA));
    nocrt::out("\r\n", 2);
    nocrt::out("secstr code B: ", 15);
    print_hex((unsigned long long)(const void*)nocrt::sec_code(kSecB));
    nocrt::out("\r\n", 2);
    if (nocrt::sec_code(kSecA) == nocrt::sec_code(kSecB)) {
        nocrt::err("secstr shares decrypt code\r\n", 30);
        return 1;
    }
    if (nocrt::fnv1a((const char*)nocrt::sec_code(kSecA), 32) ==
        nocrt::fnv1a((const char*)nocrt::sec_code(kSecB), 32)) {
        nocrt::err("secstr decrypt code identical\r\n", 33);
        return 1;
    }
    {
        nocrt::secview va(kSecA);
        nocrt::secview vb(kSecB);
        if (strcmp(va.c_str(), vb.c_str()) != 0 || strlen(va.c_str()) != 8) {
            nocrt::err("secstr decrypt failed\r\n", 23);
            return 1;
        }
        nocrt::out("secstr decrypt: ", 16);
        nocrt::out(va.c_str());
        nocrt::out("\r\n", 2);
    }

    return 0;
}
