#pragma once

#include "nocrt/nocrt.h"
#include "nocrt/stack.h"

// Freestanding DLL entries. NocrtDllEntry works under LoadLibrary and under a
// manual mapper that calls the entry with (base, DLL_PROCESS_ATTACH, 0).
// NocrtManualEntry is the manual-map path: the injector passes a pointer to
// the nocrt_config block it wrote into the target, which is how the library
// learns the CET/PT policy and its own image base without any imports.

constexpr nocrt_dword kDllProcessAttach = 1;
constexpr nocrt_dword kDllProcessDetach = 0;

extern "C" int nocrt_dll_main(nocrt_dword reason);

extern "C" __declspec(dllexport) int __stdcall NocrtDllEntry(void* hinst, nocrt_dword reason,
                                                             void* reserved) {
    // Deliberately a no-op: doing lazy resolution, pool spawns or unwind
    // registration inside DllMain runs under the loader lock and crashes or
    // deadlocks when loader-mapped. Consumers kick off work after load via
    // NocrtManualEntry (loader mode) or the mapper calls it directly
    // (manual-map mode).
    (void)hinst;
    (void)reason;
    (void)reserved;
    return 1;
}

extern "C" __declspec(dllexport) unsigned long __stdcall NocrtManualEntry(void* config) {
    nocrt::g_config = (nocrt::nocrt_config*)config;
    return (unsigned long)nocrt_dll_main(kDllProcessAttach);
}
