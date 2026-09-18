#include "nocrt/nocrt.h"
#include "nocrt/pattern.h"
#include "nocrt/pe.h"

// Companion harness: given a parent binary, grab patterns and addresses out
// of it using only the nocrt library. Demonstrates the closed loop:
//   scan for a known pattern -> report offset/RVA/VA
//   generate a signature at that address -> verify it is unique
//   re-scan with the generated signature -> confirm it resolves back
//
// Usage: patscan.exe <parent-binary>

static void print_hex(unsigned long long v) {
    const char digits[] = "0123456789abcdef";
    char buf[16];
    for (int i = 0; i < 16; ++i) buf[i] = digits[(v >> ((15 - i) * 4)) & 0xF];
    nocrt::out(buf, 16);
}

static void print_dec(unsigned long long v) {
    char buf[24];
    nocrt_size n = 0;
    if (v == 0) { nocrt::out("0", 1); return; }
    while (v) { buf[n++] = (char)('0' + (v % 10)); v /= 10; }
    char rev[24];
    for (nocrt_size i = 0; i < n; ++i) rev[i] = buf[n - 1 - i];
    nocrt::out(rev, n);
}

static void print_pattern(const nocrt::pattern_byte* p, nocrt_size n) {
    const char digits[] = "0123456789abcdef";
    for (nocrt_size i = 0; i < n; ++i) {
        if (i) nocrt::out(" ", 1);
        char two[2] = { digits[p[i].value >> 4], digits[p[i].value & 0xF] };
        nocrt::out(two, 2);
    }
}

// "nocrt: alive" - plaintext present in the demo image's .rdata.
constexpr nocrt::pattern kBanner("6E 6F 63 72 74 3A 20 61 6C 69 76 65");
constexpr nocrt_size kSigLen = 16;

extern "C" int nocrt_main() {
    char path[260];
    if (nocrt::arg(1, path, sizeof(path)) == 0) {
        nocrt::err("usage: patscan.exe <parent-binary>\r\n", 34);
        return 2;
    }

    nocrt::mapped_pe pe;
    if (!pe.open(path)) {
        nocrt::err("patscan: cannot map parent binary\r\n", 36);
        return 2;
    }
    nocrt::out("parent mapped, bytes: ", 22);
    print_dec(pe.size);
    nocrt::out(", imagebase: ", 13);
    print_hex(pe.image_base);
    nocrt::out("\r\n", 2);

    const unsigned char* hit = nocrt::scan(pe.base, pe.size, kBanner);
    if (!hit) {
        nocrt::err("patscan: banner pattern not found\r\n", 35);
        pe.close();
        return 1;
    }
    const nocrt_size off = (nocrt_size)(hit - pe.base);
    nocrt::out("pattern hit file-off: ", 22);
    print_hex(off);
    nocrt::out(" rva: ", 6);
    print_hex(pe.rva_from_offset(off));
    nocrt::out(" va: ", 5);
    print_hex(pe.va_from_offset(off));
    nocrt::out("\r\n", 2);

    nocrt::pattern_byte sig[kSigLen];
    for (nocrt_size i = 0; i < kSigLen; ++i) {
        sig[i].value = hit[i];
        sig[i].any = false;
    }
    nocrt::out("generated signature: ", 21);
    print_pattern(sig, kSigLen);
    nocrt::out("\r\n", 2);

    const nocrt_size uniq = nocrt::count_matches(pe.base, pe.size, sig, kSigLen);
    nocrt::out("signature occurrences: ", 23);
    print_dec(uniq);
    nocrt::out("\r\n", 2);
    if (uniq != 1) {
        nocrt::err("patscan: signature not unique\r\n", 30);
        pe.close();
        return 1;
    }

    const unsigned char* again = nocrt::scan(pe.base, pe.size, sig, kSigLen);
    if (again != hit) {
        nocrt::err("patscan: re-scan mismatch\r\n", 28);
        pe.close();
        return 1;
    }
    nocrt::out("patscan: PASS - pattern, address and signature round-trip ok\r\n", 61);
    pe.close();
    return 0;
}
