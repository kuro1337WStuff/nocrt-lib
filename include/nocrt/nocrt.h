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
__declspec(dllimport) char* __stdcall GetCommandLineA();
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

// Little-endian byte readers; the PE and lazy-import walkers build on these.
inline unsigned short rd16(const unsigned char* p) {
    return (unsigned short)((unsigned short)p[0] | ((unsigned short)p[1] << 8));
}
inline unsigned long rd32(const unsigned char* p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) |
           ((unsigned long)p[3] << 24);
}
inline unsigned long long rd64(const unsigned char* p) {
    return (unsigned long long)rd32(p) | ((unsigned long long)rd32(p + 4) << 32);
}

// murmur-style finalizer mix; constexpr so callers can fold it at compile time.
constexpr unsigned long long xmix(unsigned long long s) {
    s ^= s >> 33;
    s *= 0xFF51AFD7ED558CCDull;
    s ^= s >> 33;
    s *= 0xC4CEB9FE1A85EC53ull;
    s ^= s >> 33;
    return s;
}

// Per-expansion-site seed. Research fold-in 2026-09-17: seeds must NOT be
// derivable from __LINE__ alone (an adversary brute-forced line x counter in
// ~1.7k tries). Mix in a per-build salt so the keyspace is not the source line
// number and ciphertext differs across builds. Override NOCRT_SALT for
// reproducible builds.
constexpr unsigned long long build_salt() {
    const char* d = __DATE__;
    const char* t = __TIME__;
    unsigned long long h = 0xCBF29CE484222325ull;
    for (nocrt_size i = 0; d[i]; ++i) {
        h ^= (unsigned char)d[i];
        h *= 0x100000001B3ull;
    }
    for (nocrt_size i = 0; t[i]; ++i) {
        h ^= (unsigned char)t[i];
        h *= 0x100000001B3ull;
    }
    return xmix(h);
}

#ifndef NOCRT_SALT
#define NOCRT_SALT ::nocrt::build_salt()
#endif

constexpr unsigned long long line_seed(unsigned long long line) {
    return xmix(line * 0x1000003B9ull ^ NOCRT_SALT);
}

// Every Win32 call goes through this table. In the default build it is filled
// from the static kernel32 imports; with NOCRT_ZERO_IMPORT=1 it is filled by
// lazy PEB/export resolution, so the image carries no import table at all.
struct api_table {
    nocrt_handle(__stdcall* get_std_handle)(nocrt_dword);
    nocrt_dword(__stdcall* write_file)(nocrt_handle, const void*, nocrt_dword, nocrt_dword*, void*);
    void(__stdcall* exit_process)(nocrt_dword);
    char*(__stdcall* get_command_line_a)();
};

api_table& api();

inline bool write(nocrt_handle file, const char* data, nocrt_size n) {
    nocrt_dword written = 0;
    return api().write_file(file, data, (nocrt_dword)n, &written, nullptr) != 0;
}

inline bool out(const char* data, nocrt_size n) {
    return write(api().get_std_handle(NOCRT_STD_OUTPUT_HANDLE), data, n);
}

inline bool out(const char* data) { return out(data, strlen(data)); }

// sizeof-folded literal emit: kills hand-counted length literals as a bug
// class (seven wrong call sites were corrupting committed logs).
template <nocrt_size N>
inline bool say(const char (&s)[N]) {
    return out(s, N - 1);
}

inline bool err(const char* data, nocrt_size n) {
    return write(api().get_std_handle(NOCRT_STD_ERROR_HANDLE), data, n);
}

inline bool err(const char* data) { return err(data, strlen(data)); }

// Command line without CRT startup: read the raw process command line.
inline const char* cmdline() { return api().get_command_line_a(); }

// Copies the n-th whitespace-separated token (0 = image path) into out.
// Quoted tokens are unwrapped. Returns the copied length, 0 if absent.
inline nocrt_size arg(nocrt_size n, char* out, nocrt_size cap) {
    if (cap) out[0] = 0;
    const char* p = cmdline();
    nocrt_size idx = 0;
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        char quote = 0;
        if (*p == '"') { quote = '"'; ++p; }
        const char* start = p;
        while (*p && (quote ? *p != quote : (*p != ' ' && *p != '\t'))) ++p;
        const nocrt_size len = (nocrt_size)(p - start);
        if (quote && *p == '"') ++p;
        if (idx == n) {
            const nocrt_size c = len < cap - 1 ? len : cap - 1;
            for (nocrt_size i = 0; i < c; ++i) out[i] = start[i];
            out[c] = 0;
            return c;
        }
        ++idx;
    }
    return 0;
}

} // namespace nocrt

// Implemented by the consuming project. The nocrt entry point calls this
// instead of main(), then terminates the process directly.
extern "C" int nocrt_main();
