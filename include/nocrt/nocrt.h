#pragma once

// nocrt - freestanding C++ for Windows user mode.
//
// No CRT startup, no default libraries, no <cstring>/<cstdio>/<new>.
// The only imports are raw Win32 entries resolved from kernel32, so the
// resulting image carries a minimal, fully auditable import table.

using nocrt_size = unsigned long long;
using nocrt_handle = void*;
using nocrt_dword = unsigned long;

extern "C" {
__declspec(dllimport) nocrt_handle __stdcall GetStdHandle(nocrt_dword which);
__declspec(dllimport) nocrt_dword __stdcall WriteFile(nocrt_handle file, const void* buffer,
                                                      nocrt_dword to_write, nocrt_dword* written,
                                                      void* overlapped);
__declspec(dllimport) void __stdcall ExitProcess(nocrt_dword code);
}

#define NOCRT_STD_OUTPUT_HANDLE ((nocrt_dword)-11)
#define NOCRT_STD_ERROR_HANDLE ((nocrt_dword)-12)

// Provided by src/nocrt.cpp at global scope so that implicit compiler
// generated calls (structure copies, constant copies) resolve without the CRT.
extern "C" {
void* __cdecl memset(void* dst, int value, nocrt_size n);
void* __cdecl memcpy(void* dst, const void* src, nocrt_size n);
void* __cdecl memmove(void* dst, const void* src, nocrt_size n);
int __cdecl memcmp(const void* a, const void* b, nocrt_size n);
nocrt_size __cdecl strlen(const char* s);
int __cdecl strcmp(const char* a, const char* b);
int __cdecl strncmp(const char* a, const char* b, nocrt_size n);
}

namespace nocrt {

inline bool write(nocrt_handle file, const char* data, nocrt_size n) {
    nocrt_dword written = 0;
    return WriteFile(file, data, (nocrt_dword)n, &written, nullptr) != 0;
}

inline bool out(const char* data, nocrt_size n) {
    return write(GetStdHandle(NOCRT_STD_OUTPUT_HANDLE), data, n);
}

inline bool out(const char* data) { return out(data, strlen(data)); }

inline bool err(const char* data, nocrt_size n) {
    return write(GetStdHandle(NOCRT_STD_ERROR_HANDLE), data, n);
}

inline bool err(const char* data) { return err(data, strlen(data)); }

} // namespace nocrt

// Implemented by the consuming project. The nocrt entry point calls this
// instead of main(), then terminates the process directly.
extern "C" int nocrt_main();
