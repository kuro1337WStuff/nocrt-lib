#pragma once

#include "nocrt/nocrt.h"
#include "nocrt/lazy.h"

// Thread-origin hygiene. A thread whose start address sits in our region is a
// tell; queueing work to the system thread pool puts the start address in
// ntdll/kernel32 worker code instead. Explicit threads are the fallback.

namespace nocrt {

using ThreadStart = unsigned long(__stdcall*)(void*);

inline bool spawn_on_pool(ThreadStart fn, void* ctx) {
    const auto f = (int(__stdcall*)(ThreadStart, void*, void*))NOCRT_FN(
        "TrySubmitThreadpoolCallback");
    if (!f) return false;
    return f(fn, ctx, nullptr) != 0;
}

inline bool spawn_thread(ThreadStart fn, void* ctx, void** thread_out) {
    const auto f = (void*(__stdcall*)(void*, ThreadStart, void*))NOCRT_FN("CreateThread");
    if (!f) return false;
    void* t = f(nullptr, fn, ctx);
    if (thread_out) *thread_out = t;
    return t != nullptr;
}

inline bool spawn(ThreadStart fn, void* ctx, void** thread_out) {
    if (spawn_on_pool(fn, ctx)) {
        if (thread_out) *thread_out = nullptr;
        return true;
    }
    return spawn_thread(fn, ctx, thread_out);
}

} // namespace nocrt
