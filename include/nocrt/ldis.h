#pragma once

#include "nocrt/nocrt.h"
#include "hde/hde64.h"

// Restricted prologue probe on top of the vendored public-domain HDE64
// length decoder (third_party/hde, MinHook). HDE gives length only; the
// RIP-relative and branch checks below are the additions the engine survey
// calls the single highest-value thing HDE does not give you.
//
// probe_prologue refuses (ok=false, reason set) when the stolen range would
// contain a RIP-relative operand, a branch, an unsupported stack operation,
// or exceed 16 bytes. Refusals are data, not crashes: the consumer logs them.

namespace nocrt {

struct nocrt_prologue {
    nocrt_size stolen;
    unsigned char push_regs[8];
    unsigned char push_offsets[8];
    unsigned char push_count;
    unsigned long alloc_size;
    unsigned char alloc_offset;
    bool ok;
    unsigned long reason;  // 0 ok | 1 rip-rel | 2 branch | 3 bad stack op | 4 too long
};

inline nocrt_prologue probe_prologue(const unsigned char* p, nocrt_size need) {
    nocrt_prologue pr = {};
    nocrt_size off = 0;
    while (off < need) {
        hde64s hs = {};
        const unsigned int len = hde64_disasm(p + off, &hs);
        if (!len || (hs.flags & 0x00008000) /*HDE64F_ERROR*/) {
            pr.reason = 3;
            return pr;
        }
        const unsigned char op = hs.opcode;
        const unsigned char mod = (unsigned char)(hs.modrm >> 6);
        const unsigned char rm = (unsigned char)(hs.modrm & 7);
        const unsigned char reg = (unsigned char)((hs.modrm >> 3) & 7);
        // RIP-relative memory operand
        if (hs.modrm && mod != 3) {
            const bool rip_rel = (mod == 0 && rm == 5) ||
                                 (mod == 0 && rm == 4 && (hs.sib & 7) == 5);
            if (rip_rel) {
                pr.reason = 1;
                return pr;
            }
        }
        // Branches / returns / indirect jumps
        if (op == 0xE8 || op == 0xE9 || op == 0xEB || op == 0xC2 || op == 0xC3 || op == 0xCC ||
            (op == 0x0F && hs.opcode2 >= 0x80 && hs.opcode2 <= 0x8F) ||
            (op == 0xFF && (reg == 4 || reg == 5))) {
            pr.reason = 2;
            return pr;
        }
        // push nonvol
        if (op >= 0x50 && op <= 0x57 && !hs.modrm) {
            if (pr.push_count < 8) {
                pr.push_regs[pr.push_count] =
                    (unsigned char)((op - 0x50) + ((hs.rex & 1) ? 8 : 0));
                pr.push_offsets[pr.push_count] = (unsigned char)(off + len);
                ++pr.push_count;
            }
        } else if ((op == 0x83 || op == 0x81) && reg == 5 && hs.sib &&
                   (hs.sib & 7) == 4 /*rsp*/) {
            if (pr.alloc_size) {
                pr.reason = 3;
                return pr;
            }
            pr.alloc_size = (op == 0x83) ? (unsigned long)hs.imm.imm8
                                         : (unsigned long)hs.imm.imm32;
            pr.alloc_offset = (unsigned char)(off + len);
        } else if (op == 0x83 || op == 0x81) {
            // arithmetic on a non-rsp target inside a prologue: refuse
            pr.reason = 3;
            return pr;
        }
        off += len;
        if (off > 16) {
            pr.reason = 4;
            return pr;
        }
    }
    pr.stolen = off;
    pr.ok = pr.stolen >= need;
    return pr;
}

} // namespace nocrt
