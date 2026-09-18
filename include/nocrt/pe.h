#pragma once

#include "nocrt/nocrt.h"

// CRT-free PE mapping: open a binary on disk, map it read-only, and translate
// file offsets to RVAs/VAs by walking the section table. No <windows.h>, no
// CRT, kernel32 imports only.

namespace nocrt {

extern "C" {
__declspec(dllimport) nocrt_handle __stdcall CreateFileA(const char* path, unsigned long access,
                                                         unsigned long share, void* security,
                                                         unsigned long disposition, unsigned long flags,
                                                         nocrt_handle template_file);
__declspec(dllimport) nocrt_handle __stdcall CreateFileMappingA(nocrt_handle file, void* attrs,
                                                                unsigned long protect,
                                                                unsigned long hi, unsigned long lo,
                                                                const char* name);
__declspec(dllimport) void* __stdcall MapViewOfFile(nocrt_handle mapping, unsigned long access,
                                                    unsigned long hi, unsigned long lo, nocrt_size bytes);
__declspec(dllimport) int __stdcall UnmapViewOfFile(const void* base);
__declspec(dllimport) int __stdcall CloseHandle(nocrt_handle h);
__declspec(dllimport) unsigned long __stdcall GetFileSize(nocrt_handle file, unsigned long* high);
}

const nocrt_handle kInvalidHandle = (nocrt_handle)(long long)-1;
constexpr unsigned long kGenericRead = 0x80000000u;
constexpr unsigned long kFileShareRead = 0x00000001u;
constexpr unsigned long kOpenExisting = 3;
constexpr unsigned long kPageReadOnly = 0x02;
constexpr unsigned long kFileMapRead = 0x0004;

struct mapped_pe {
    const unsigned char* base = nullptr;
    nocrt_size size = 0;
    unsigned long long image_base = 0;
    const unsigned char* sections = nullptr;
    unsigned short section_count = 0;
    nocrt_handle file = kInvalidHandle;
    nocrt_handle mapping = kInvalidHandle;

    bool open(const char* path) {
        file = CreateFileA(path, kGenericRead, kFileShareRead, nullptr, kOpenExisting, 0, kInvalidHandle);
        if (file == kInvalidHandle) return false;
        size = GetFileSize(file, nullptr);
        mapping = CreateFileMappingA(file, nullptr, kPageReadOnly, 0, 0, nullptr);
        if (mapping == kInvalidHandle) { close(); return false; }
        base = (const unsigned char*)MapViewOfFile(mapping, kFileMapRead, 0, 0, 0);
        if (!base) { close(); return false; }
        return parse_headers();
    }

    void close() {
        if (base) { UnmapViewOfFile(base); base = nullptr; }
        if (mapping != kInvalidHandle) { CloseHandle(mapping); mapping = kInvalidHandle; }
        if (file != kInvalidHandle) { CloseHandle(file); file = kInvalidHandle; }
        size = 0;
        sections = nullptr;
        section_count = 0;
        image_base = 0;
    }

    // File offset -> RVA via the section table (raw -> virtual).
    unsigned long rva_from_offset(nocrt_size off) const {
        for (unsigned short i = 0; i < section_count; ++i) {
            const unsigned char* s = sections + (nocrt_size)i * 40;
            const unsigned long va = rd32(s + 12);
            const unsigned long raw_size = rd32(s + 16);
            const unsigned long raw_ptr = rd32(s + 20);
            if (off >= raw_ptr && off < raw_ptr + raw_size) {
                return va + (unsigned long)(off - raw_ptr);
            }
        }
        return (unsigned long)off;
    }

    unsigned long long va_from_offset(nocrt_size off) const {
        return image_base + rva_from_offset(off);
    }

    // RVA -> file offset via the section table (virtual -> raw). Lets the
    // export walker parse a file-mapped image, not just a live module.
    nocrt_size offset_from_rva(unsigned long rva) const {
        for (unsigned short i = 0; i < section_count; ++i) {
            const unsigned char* s = sections + (nocrt_size)i * 40;
            const unsigned long va = rd32(s + 12);
            const unsigned long raw_size = rd32(s + 16);
            const unsigned long raw_ptr = rd32(s + 20);
            if (rva >= va && rva < va + raw_size) {
                return raw_ptr + (nocrt_size)(rva - va);
            }
        }
        return (nocrt_size)rva;
    }

private:
    bool parse_headers() {
        if (size < 64) return false;
        if (base[0] != 'M' || base[1] != 'Z') return false;
        const unsigned long lfanew = rd32(base + 0x3C);
        if (lfanew + 24 + 20 + 24 > size) return false;
        const unsigned char* nt = base + lfanew;
        if (rd32(nt) != 0x4550) return false; // "PE\0\0"
        const unsigned char* fh = nt + 4;
        section_count = rd16(fh + 2);
        const unsigned short opt_size = rd16(fh + 16);
        const unsigned char* opt = nt + 24;
        if ((nocrt_size)(opt - base) + opt_size > size) return false;
        const unsigned short magic = rd16(opt);
        image_base = (magic == 0x20B) ? rd64(opt + 24) : (unsigned long long)rd32(opt + 28);
        sections = opt + opt_size;
        if ((nocrt_size)(sections - base) + (nocrt_size)section_count * 40 > size) return false;
        return true;
    }
};

} // namespace nocrt
