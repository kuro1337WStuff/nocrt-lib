# nocrt

Freestanding C++ for Windows user mode. No CRT startup, no standard library,
no default libraries — just your code and a minimal, fully auditable import
table.

The goal is a library that lets a project do what a normal C++ program does
while linking **nothing** from the C runtime. The resulting image imports
only what you explicitly reach for (today: `KERNEL32.dll`), so there is no
CRT module, no CRT startup code, and no CRT import surface in the binary.

## Verified state

The demo builds with MSVC 2022 and links with `/NODEFAULTLIB`. The import
table of the produced executable contains exactly one module:

```
=== import table (must show KERNEL32 only) ===
    KERNEL32.dll
```

Running it exercises the freestanding primitives and self-tests them:

```
nocrt: alive - no CRT linked
memcpy/memset/strlen work: ok
```

## Build

Requires Visual Studio 2022 (any edition; the script points at Community —
edit `build.bat` if yours differs).

```
build.bat
```

The flags that make it freestanding:

| Flag | Purpose |
|---|---|
| `/NODEFAULTLIB` | drop every default library, including the CRT |
| `/ENTRY:nocrt_entry` | replace CRT startup with our own entry |
| `/SUBSYSTEM:CONSOLE` | no CRT startup exists to imply a subsystem |
| `/Oi-` | stop MSVC treating `memcpy`/`memset`/... as intrinsics so we can define them |
| `/GS-` | no buffer-security cookie (a CRT symbol) |
| `/EHs-c-` `/GR-` | no exceptions, no RTTI — both lean on the CRT |

## Layout

```
include/nocrt/nocrt.h   freestanding primitives + minimal Win32 declarations
src/nocrt.cpp           global memcpy/memset/memmove/memcmp/strlen/strcmp/strncmp
src/entry.cpp           nocrt_entry: calls nocrt_main, then ExitProcess
src/demo.cpp            nocrt_main + self-test
build.bat               vcvars64 + NoCRT compile + import-table dump
```

## Model

A consuming project implements `extern "C" int nocrt_main();`. The nocrt
entry point calls it and terminates the process directly — there is no
`main`, no argc/argv, no static initializers, no atexit.

Implicit compiler-emitted block copies resolve against the real symbols in
`src/nocrt.cpp`, which is why they are defined at global scope rather than
hidden in a namespace.

## Roadmap

The living feature list, design notes, and verification log live in
[`docs/FEATURES.md`](docs/FEATURES.md). Headline capability today:
compile-time polymorphic XOR strings (`NOCRT_XSTR` / `nocrt::xdec`).

## Non-goals

- It is not a drop-in replacement for the standard library; code must be
  written against `nocrt::` primitives.
- It does not target MinGW/GCC; the technique here is MSVC-specific.
