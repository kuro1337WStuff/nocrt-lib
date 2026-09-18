#include "nocrt/nocrt.h"
#include "nocrt/pattern.h"
#include "nocrt/pe.h"
#include "nocrt/hostcrt.h"

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
    char mode[16];
    bool crt_mode = false;
    nocrt::arg(1, mode, sizeof(mode));
    if (strcmp(mode, "--crt") == 0) {
        crt_mode = true;
        if (nocrt::arg(2, path, sizeof(path)) == 0) {
            nocrt::err("usage: patscan.exe --crt <crt-dll> <func>\r\n", 42);
            return 2;
        }
    } else if (nocrt::arg(1, path, sizeof(path)) == 0) {
        nocrt::err("usage: patscan.exe <parent-binary> | --crt <crt-dll> <func>\r\n", 58);
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

    if (crt_mode) {
        // Resolve printf out of a real CRT image two independent ways - the
        // export-directory walker (with section fixup for file mappings) and
        // a pattern scan derived from the resolved bytes - and require them
        // to agree. This is the host-CRT reachability proof.
        struct file_rva {
            const nocrt::mapped_pe* pe;
            const unsigned char* operator()(unsigned long rva) const {
                return pe->base + pe->offset_from_rva(rva);
            }
        };
        char fnname[64];
        if (nocrt::arg(3, fnname, sizeof(fnname)) == 0) {
            nocrt::err("usage: patscan.exe --crt <crt-dll> <func>\r\n", 42);
            pe.close();
            return 2;
        }
        const unsigned long long want =
            nocrt::lazy_detail::hash_name(fnname, nocrt::kHostCrtSeed);
        const unsigned char* fn = nocrt::lazy_detail::resolve_exports(
            pe.base, file_rva{&pe}, want, nocrt::kHostCrtSeed);
        if (!fn) {
            nocrt::err("patscan: function not resolved in crt image\r\n", 46);
            pe.close();
            return 1;
        }
        const nocrt_size foff = (nocrt_size)(fn - pe.base);
        nocrt::out("resolved file-off: ", 19);
        print_hex(foff);
        nocrt::out(" rva: ", 6);
        print_hex(pe.rva_from_offset(foff));
        nocrt::out("\r\n", 2);
        if (!nocrt::cross_check(pe.base, pe.size, fn, 16)) {
            nocrt::err("patscan: crt cross-check failed\r\n", 35);
            pe.close();
            return 1;
        }
        nocrt::out("patscan: PASS - export-hash and pattern-scan agree on host CRT\r\n", 64);
        pe.close();
        return 0;
    }

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
