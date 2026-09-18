# nocrt-lib — Features & Design Notes

Living document. Every capability lands here with a checkbox; design decisions
and gotchas go in the notes so the vision survives across sessions.

## Shipped

- [x] **Freestanding build** — `/NODEFAULTLIB`, custom entry (`nocrt_entry`),
      `/SUBSYSTEM:CONSOLE`, `/Oi- /GS- /EHs-c- /GR-`. Import table is
      `KERNEL32.dll` only.
- [x] **Byte primitives as real global symbols** — `memcpy memset memmove
      memcmp strlen strcmp strncmp`, so implicit compiler-emitted block copies
      link without the CRT.
- [x] **Console I/O without CRT** — `nocrt::out` / `nocrt::err` over raw
      `WriteFile` + `GetStdHandle`.
- [x] **Compile-time polymorphic XOR strings** — `NOCRT_XSTR("...")` encrypts
      the literal during compilation; `nocrt::xdec` decrypts at runtime into a
      stack buffer zeroed on scope exit. See "The string story" below.
- [x] **FNV-1a hash** — `nocrt::fnv1a`, constexpr.
- [x] **Runtime pattern scanning** — IDA-style patterns parsed at compile time
      (`nocrt::pattern`), wildcard scan + match counting over any memory range,
      and a `rel32` RIP-relative resolver.
- [x] **CRT-free PE mapping** — `nocrt::mapped_pe`: read-only file map, DOS/NT
      header + section-table parse, file-offset → RVA → VA translation.
- [x] **Command line without CRT** — `nocrt::cmdline()` / `nocrt::arg(n, ...)`
      over raw `GetCommandLineA`, with quote handling.
- [x] **Companion harness `tools/patscan`** — grabs patterns and addresses out
      of a parent binary using only the library: scan a known pattern →
      file-off/RVA/VA, generate a signature at that address, verify uniqueness,
      re-scan to confirm the round trip.
- [x] **Lazy import resolution (`include/nocrt/lazy.h`)** — PEB → LDR module
      walk plus export-directory parse; function names matched by a constexpr
      hash seeded per expansion site (`NOCRT_FN("WriteFile")`), so the baked
      immediates are not a stable signature the way stock lazy-importer
      headers are. Forwarded exports are detected and rejected.
- [x] **Zero-import build mode (`NOCRT_ZERO_IMPORT=1`)** — every Win32 call
      routed through the `nocrt::api()` table, filled on first use by lazy
      resolution; links with no libraries at all and `dumpbin /imports` shows
      an empty table.

## The string story (headline feature)

Goal: strings behave polymorphically **at compile time** using XOR +
`constexpr`.

How it works:
- `xmix` (murmur-style finalizer) and `xkey_byte` are `constexpr`, so the XOR
  encryption is performed by the compiler, not at runtime.
- The seed is `xseed(__LINE__, __COUNTER__)` at each macro expansion, so two
  expansions of the *same* literal encrypt to *different* ciphertext. That is
  the polymorphism: no stable byte signature for a repeated string.
- Because the `xstr` object is `constexpr`, only the encrypted bytes are
  emitted into `.rdata`. The plaintext literal is consumed by constant
  evaluation and never reaches the image.
- `xdec` holds plaintext only in a stack buffer and `memset`s it to zero in
  its destructor, so plaintext lifetime is scoped and brief.

Verified:
- ciphertext of `"polymorphic"` at two sites: fnv1a `1631aa904d599eba` vs
  `ee463a3329348dc1` — different, as required.
- both decrypt to the same correct plaintext.
- byte-search of the built exe: `polymorphic` **not present**.

### Gotcha (important)

Protection is opt-in per literal. A plain `const char* s = "text";` still
emits plaintext into the image (verified: `freestanding` was found in the
exe). Only `NOCRT_XSTR`-wrapped literals are encrypted. A future lint or
compiler-side check for unwrapped literals is a candidate feature.

## Planned — the standard-library surface for NoCRT

The end goal: a C++ app can use strings and everything else it expects from a
standard library, with no CRT linked. Candidate pieces, grouped:

**Strings & text**
- [ ] string type: fixed-capacity (no heap) and heap-backed variants
- [ ] concat / compare / find / slice / trim
- [ ] char classification & case: `isdigit isalpha toupper tolower`
- [ ] parsing: `atoi strtol strtoull` and float parse
- [ ] formatting: integer/hex to string, `snprintf`-equivalent without CRT

**Containers**
- [ ] `static_vector` (fixed capacity, zero allocation)
- [ ] `vector` (heap-backed, once allocator lands)
- [ ] `span`, `array`
- [ ] small open-addressing map keyed by hash

**Memory & allocation**
- [ ] heap allocator over `HeapAlloc`/`HeapFree`
- [ ] page allocator over `VirtualAlloc` for large / guarded regions
- [ ] aligned alloc, secure zero

**Numbers & math**
- [ ] `abs min max clamp`, integer sqrt, pow-by-squaring
- [ ] float basics without CRT helpers

**OS & I/O**
- [ ] runtime API resolution by hash (`GetProcAddress`) so the import table
      stays `KERNEL32`-only even as we use more modules
- [ ] file I/O: `CreateFile ReadFile WriteFile` wrappers
- [ ] time: `QueryPerformanceCounter`, system time, sleep
- [ ] last-error access

**Sync & concurrency**
- [ ] SRW lock / critical section wrappers
- [ ] atomics & memory-order helpers

**Unicode**
- [ ] UTF-8 <-> UTF-16 via `WideCharToMultiByte` / `MultiByteToWideChar`
      (resolved dynamically)

**Random & crypto**
- [ ] xorshift / splitmix PRNG (no CRT `rand`)
- [ ] crc32, djb2 alongside fnv1a
- [ ] optionally `RtlGenRandom` resolved dynamically

**Algorithms**
- [ ] sort / search / lower_bound over spans

## Design notes

- Keep the import table at `KERNEL32` only; anything else is resolved at
  runtime by hash. This is central to the project's purpose.
- Prefer fixed-capacity containers until the allocator exists; allocation is
  a dependency, not a convenience.
- Every feature ships with a self-test in `src/demo.cpp` and a checkbox here.
- Compile-time work belongs in `constexpr`; runtime plaintext must be scoped
  and zeroed.
- Zero-import stays opt-in (`NOCRT_ZERO_IMPORT`), not the default: an empty
  import table is itself anomalous to some heuristics, so the kernel32-minimal
  build remains the default profile. Lazy resolution is the capability; the
  build mode is a policy choice per consumer.

## Verification log

- 2026-09-18: build OK; imports `KERNEL32.dll` only; demo self-tests pass;
  xstr ciphertext differs per site; plaintext `polymorphic` absent from exe;
  naive literal `freestanding` present (documents the opt-in gotcha).
- 2026-09-18: `patscan` round-trip PASS against `nocrt-demo.exe` as parent —
  banner pattern hit file-off `0x1258` / rva `0x2058` / va `0x140002058`;
  generated 16-byte signature unique (occurrences 1); re-scan resolved to the
  same address. Both images import `KERNEL32.dll` only.
- 2026-09-18: lazy/zero-import verified — `nocrt-zero.exe` links with no
  libraries, `dumpbin /imports` empty, and runs byte-identical output to the
  kernel32-minimal demo (GetStdHandle/WriteFile/ExitProcess/GetCommandLineA
  all resolved via the PEB walk). `patscan` PASS against the zero-import image
  (hit rva `0x3078`).

## v1 stealth + harness (shipped 2026-09-17)

- [x] **Hardened strings `secstr`** — per-string distinct decrypt CODE: 6 ops
      ^ 5 steps = 7776 operation programs seeded per expansion site;
      `NOCRT_SECSTR` + scoped `secview`. Demo proves distinct ciphertext AND
      distinct 32-byte code hashes per site; plaintext absent from images.
- [x] **Host-CRT reachability `hostcrt.h`** — locate host CRT modules by UTF-16
      name hash in the PEB, resolve exports by hash, call them with decrypted
      strings. `patscan --crt` cross-checks export-hash vs pattern-scan on real
      CRT images (ucrtbase!puts, msvcrt!printf PASS).
- [x] **Image-backed mapping `map.h`** — SEC_IMAGE section map (MEM_IMAGE VAD)
      plus header wipe. Measured: cross-process SEC_IMAGE execute mapping is
      DENIED on this system (0xC0000022), so the injector falls back to private
      manual mapping; APC self-map for MEM_IMAGE is the roadmap fix.
- [x] **Thread-origin hygiene `thread.h`** — work queued via
      TrySubmitThreadpoolCallback so thread start addresses live in system
      worker code; CreateThread fallback.
- [x] **Hook engine `hook.h`** — inline detour+trampoline (trampoline allocated
      within +/-2GB of target), HWBP+VEH and guard-page+VEH zero-write modes,
      unhook/restore, self-integrity check. Compile-time selectable.
- [x] **Stack layer `stack.h` + `tools/stackwalk`** — CET CPU capability via
      CPUID, per-process shadow-stack/PT policy passed by injector (never
      assumed), RtlAddFunctionTable register/unregister toggle, frame walk +
      unbacked-frame classification.
- [x] **Harness** — `tools/host` (CRT, /MD), `tools/testdll` (zero-import DLL),
      `tools/inject` (section-map then private-map fallback, config block,
      remote thread), `tools/metrics` (M-lines).
- [x] **Binary hygiene** — `/Zl`, `/OPT:REF,ICF`, `/DEBUG:NONE`, post-link strip
      of Rich header + all debug directories. `/GL`+`/LTCG` impossible: C2268
      vs redefined compiler library helpers.

### Live injection result (2026-09-17)

Injected `testdll.dll` into running `host.exe`: strings decrypted in-process,
`ucrtbase!puts` resolved by export hash and called with a decrypted string,
`host_target` located by pattern in the host image and inline-hooked, host
control flow changed (`host_target` returns 1337). Walk reports 1 unbacked
frame (our worker) — the measured tell, not hidden.

### Metrics (tools/metrics, 2026-09-17)

| image | M1 mods/funcs | M2 crt strings | M3 plaintext | M10 bytes |
|---|---|---|---|---|
| nocrt-demo.exe | 1 / 4 | 0 | 0 / 0 | 10752 |
| patscan.exe | 1 / 10 | 0 | 0 / 0 | 9728 |
| nocrt-zero.exe | 0 / 0 | 0 | 0 / 0 | 11776 |
| testdll.dll | 0 / 0 | 0 | 0 / 0 | 11776 |

M7: reloc directory 0/0 on all four — valid for x64 RIP-relative images with
empty `.data`; SEC_IMAGE mapping still rebases, private mapping applies no
fixups because none exist.

### Measured limitations (honest)

- Cross-process SEC_IMAGE execute mapping denied here (0xC0000022); v1 ships
  private mapping (MEM_PRIVATE tell remains). Roadmap: APC self-map.
- A `/MT` host hides its CRT inside the exe; export-hash reachability needs a
  `/MD` host (or pattern-scanning the host's static CRT, roadmap).
- `ucrtbase.dll` on this system exports `puts` but not `printf`; `msvcrt.dll`
  exports the full family but is not loaded by modern CRT hosts.
- Runtime `str_hash` over a literal materializes the plaintext in `.rdata`;
  all name hashes must fold at compile time (template parameters). Caught by
  M2 during development.
- Inline trampoline copies patch_len bytes verbatim: the patch length must
  cover whole instructions at the target (no length disassembler yet).
- CET shadow stacks / Intel PT: CPU reports no CET support on this lab box
  (`cet_cpu=0`); policy is still queried per process by the injector. If
  shadow stacks are active, return-address spoofing would fault — spoofing
  paths stay gated on that policy.
