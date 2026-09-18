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

## Research fold-in 1 — detection vectors (2026-09-17)

Independent research agent ranked the vectors that actually catch a
manually-mapped, zero-import DLL. Corrections to earlier design notes are
marked CORRECTED; new constraints are ADOPTED.

Ranked (highest risk first): (1) MEM_PRIVATE executable memory / unbacked
image; (2) in-memory PE-header scan of unrecognized regions (zero imports is
itself an anomaly); (3) module-list vs VAD cross-check both directions;
(4) thread start address outside known modules; (5) target `.text` integrity
checksumming; (6) working-set / SharedOriginal check (defeats "I patched a
real DLL so VirtualQuery says MEM_IMAGE"); (7) protection / region-state
flags; (8) RDTSC timing deltas; (9) PEB debug flags; (10) ThreadHideFromDebugger;
(11) VEH handler-chain enumeration; (12) injector handle enumeration;
(13) ETW provider state; (14) CPUID hypervisor bit.

- CORRECTED: header wiping is NOT recommended by default (see `map.h`
  policy comment). A sanitized header reads as hollowing evidence to
  PE-sieve/Moneta-class scanners and breaks unwinding unless
  `RtlAddFunctionTable` runs first. Prefer image-backed mapping with a real,
  plausible header.
- CORRECTED: zero imports is a *self-containedness* property (the project's
  actual goal), not primarily a stealth property — an empty import directory
  is itself anomalous to header scanners. Metrics M1/M2 still track it.
- CORRECTED: Ldr-unlinking is folklore and near-useless (VAD and
  MemorySectionName survive it); being in the module list is only safe when
  combined with image-backing. Phantom-DLL-hijack-shaped loading beats module
  stomping (stomping guarantees a file-vs-memory mismatch).
- ADOPTED: never write to a byte we don't own — no inline hooks in the target,
  no IAT patches, no VirtualProtect/guard on image pages. This is what kills
  vectors 5/6/7 at zero bytes; zero-write hooks (HWBP+VEH, guard+VEH) are the
  observation path.
- ADOPTED: HWBP stealth is paid for in DR visibility, VEH-chain visibility
  (handler address in unbacked memory points straight at us), and timing
  visibility. Public sources understate this trade; ours is now documented.
- ADOPTED: don't create threads where avoidable (thread pool / APC). Residual
  measured in our live test: pool callback pointer lives in our memory, so a
  walk shows `TppWorkerThread -> unbacked frame` — exactly the 1 unbacked
  frame M9 reports.
- ROADMAP: direct syscalls instead of hooking ntdll (~500-900B stub gen + SSN
  resolution); mapper-supplied resolved-API table so the DLL need not walk the
  PEB at all (the PEB walk byte pattern is heavily signatured); injector-side
  mitigation-policy query (ACG/CIG) before choosing a mapping strategy.
- VERIFY EMPIRICALLY before committing architecture: (a) whether
  NtSetContextThread leaves Win32StartAddress unchanged on this build;
  (b) DR-breakpoint behavior on a thread that called ThreadHideFromDebugger
  (reported outcomes range from "VEH still fires" to infinite #DB loop).

## Research fold-in 2 — adversarial string recovery (2026-09-17)

An adversarial agent attacked the string scheme and recovered everything.
Scope note: it analyzed the pre-`secstr` binaries, so its timings describe
`xstr`; the structural critiques apply to `secstr` as well. Verdict: **~2 min
dynamic (breakpoint WriteFile), ~15 min static with the header, <=30 min
without source.** Findings and responses:

- **The key ships in the image.** Symmetric XOR whose only secret is a 64-bit
  seed, present as a `mov rax, imm64` and as a `.rdata` qword. This is
  obfuscation of a published constant, not encryption. ACCEPTED as the threat
  model: `xstr`/`secstr` defeat passive `strings`/grep/AV-signature scanning of
  the on-disk image and nothing more. Real encryption needs an external key or
  a white-box construction; out of scope for v1, recorded as the ceiling.
- **Seed derived from `__LINE__` collapsed the keyspace to ~1.7k** (line x
  counter brute force, byte-exact recovery). FIXED: `line_seed` now mixes a
  per-build salt from `__DATE__`/`__TIME__` (`build_salt`, overridable via
  `NOCRT_SALT`), so the keyspace is no longer the source line number and
  ciphertext differs across builds (kills the cross-build lookup table).
- **Zeroization was fictional in the shipped artifact**: MSVC eliminated the
  destructor `memset` as a dead store; plaintexts survived on the stack.
  FIXED: both `xdec` and `secview` wipe via a `volatile` loop.
- **Latent cleartext leak**: an unwrapped error literal contained the protected
  word, hidden only by dead-code elimination. FIXED: replaced with a
  non-secret message.
- **What `secstr` adds over `xstr`, stated precisely**: per-string distinct
  decrypt CODE (different op sequences/constants), so reversing one routine no
  longer hands you the others for free. It does NOT stop an analyst who writes
  one generic interpreter over the public 6-op alphabet and reads each
  string's constants from its own code. Cost raised from "one reverse = all"
  to "one interpreter + per-string constant extraction".
- Remaining known leaks, accepted and documented: length in the clear,
  high-entropy aligned blobs conspicuous in `.rdata`, seed fragments visible
  to `strings`, no tamper detection on the seed immediate.

## Research fold-in 3 — anti-analysis observation set (2026-09-17)

- ADOPTED FRAMING: **observation-first, stealth-second.** Inline detours and
  hook-detection are mutually exclusive at ring 3: the moment we detour
  `NtQueryInformationProcess`, a sample running a prologue scan finds `FF 25`
  where `4C 8B D1` should be. The deliverable reports honestly that our hooks
  are visible, detects when the sample notices (prologue sweep, ntdll-remap
  chain, VAD walks), and marks coverage terminated at that point — rather
  than claiming stealth we do not have.
- One generic trampoline covers ~80% of the observation list: every `ntdll!Nt*`
  stub shares the same prologue shape, so per-API work is only argument
  marshalling. Ranked top hooks (prevalence x analyst value): process/module
  enumeration, `NtQueryInformationProcess` 7/30/31, `ThreadHideFromDebugger`,
  firmware/disk fingerprints, ntdll-remap unhook chain, tick/sleep skew,
  single-instance mutexes, resource gates, window enumeration, ETW/AMSI
  patching, VM-artifact registry probes, parent/CommandLine inspection,
  `NtGetContextThread` DR reads, self `ReadVirtualMemory`, WMI fingerprint.
- HWBP+VEH deferred to v2, paired unconditionally with an
  `NtGetContextThread` DR-spoofing hook when shipped. Guard-page hooking
  REJECTED: dominated by both alternatives (one-shot guard needs single-step
  re-arm machinery anyway, and PAGE_GUARD is itself a tell).
- Acceptance oracle chosen: **al-khaser** as the test target — every hook that
  should fire, fires.
- Three non-hook duties adopted: own-hook integrity sweep (also detects
  FOREIGN hooks from EDRs or the sample), direct-syscall/shellcode scan over
  MEM_PRIVATE+EXECUTE regions, and an environment pre-flight assertion line.
  Every log record carries a monotonic seqno and a coverage-valid flag.
- All offsets and info-class values from the research are UNVERIFIED against
  headers; resolve dynamically at init, never hardcode.

## Research fold-in 4 — minimal PE, measured (2026-09-17)

- APPLIED: `/Gw /Zc:inline /INCREMENTAL:NO /MANIFEST:NO` and
  `/MERGE:.pdata=.rdata /MERGE:.rdata=.text`. Measured result: images drop to
  **2 sections** (`.text` chars `0x60000020` = CODE|EXECUTE|READ, no WRITE;
  `.data` pure bss, `SizeOfRawData=0`); `testdll.dll` 10240 -> 9728 B,
  `nocrt-zero.exe` 11776 -> 11264 B, `SizeOfImage` -> `0x5000`.
- `/MERGE:.reloc` is a non-issue and an error (LNK1272): our x64 images emit
  **no `.reloc` section at all** (RIP-relative codegen, empty `.data`), so
  there is nothing to merge and nothing for a mapper to fix up.
- `/FILEALIGN` DOES exist in link.exe (verified via `link /?`), correcting the
  research agent's unverified claim. Not used: on-disk padding buys little
  against normalizing static scanners.
- `/ALIGN:16` skipped BY DESIGN: sub-page SectionAlignment destroys the
  per-section RX/RW protection granularity our mapper and stealth model rely
  on, and makes the image non-LoadLibrary-able.
- Roadmap (recipe recorded, not implemented): move PE header to
  `e_lfanew=0x40` (delete DOS stub + Rich) for -184 B raw and
  `SizeOfHeaders` 1024 -> 512 (valid at <=4 sections, which we now satisfy).
- `secstr` byte cost is real: two 8-char test strings cost ~0.9-1.6 KB because
  every `sec_poskey` inlines a full `xmix`. Gate self-tests behind
  `NOCRT_SELFTEST` if a demo image ever ships; the product DLL keeps `secstr`.
- Hook engine decision: do NOT vendor MinHook/Detours/PolyHook2. Bake the
  stolen length per target using our existing pattern scanner (~250-500 B, no
  length disassembler); INT3+VEH atomic single-byte variant removes the
  thread-freeze machinery; HWBP+VEH remains the best stealth-per-byte.
- Mapper already compliant with the transient-write rule: allocate RW, apply
  copies, set final per-section protections immediately; no persistent RWX.
- STRATEGIC TENSION recorded: byte-minimization and module-size plausibility
  pull opposite ways (a 7 KB module is itself anomalous; the pad-up trick
  costs ~40 B of file for a plausible `SizeOfImage` via
  `VirtualSize > SizeOfRawData`). Which side wins depends on the scanner class
  in the threat model — decision pending (see open questions).

## Research fold-in 5 — stack-walk-safe hooking (2026-09-17)

Ranked by completeness against unwind/frame-chain walks x residual tells x
freestanding cost: (1) frame-less jmp-only inline instrumentation with
image-backed trampoline and atomic INT3 patch — needs no spoofing for
observe-and-forward; (2) HWBP+VEH observe-only with DRs installed via
NtContinue on own thread and RF-flag discipline — for checksummed targets,
<=4 slots per thread; (3) executed-gadget return-address spoofing (~60 B asm +
gadget scanner validated via RtlLookupFunctionEntry) — only when calling out
under post-call validation; (4) full synthetic chain on the real thread stack
— only on evidence the target validates frame sizes/RSP bounds; (5) IAT hooks
— niche, nearly free where applicable. Non-goals: NtContinue/RtlRestoreContext
teleportation as primary (SetContextIpValidation + EHCONT deny on modern ntdll),
CET WRSS spoofing, guard-page hooks against unknown samples (collateral traps
and VEH conflicts), Intel PT suppression (impossible), ETW-TI suppression
(impossible from user mode).

- ADOPTED at init: capability probe (`probe_caps`: CPUID CET/CET_SS, RDSSPQ
  ground truth, ProcessUserShadowStackPolicy) and `register_own_unwind`
  (RtlAddFunctionTable for our image) — without the latter our manually mapped
  frames unwind as leaves, silently corrupting walks.
- ADOPTED as rules: scratch regs rax/r10/r11 only in detours; never call from
  a frame-less detour (jmp only); restricted length decoder that REFUSES
  unknown prologue forms and logs the refusal; trampoline within +/-2GB;
  FlushInstructionCache after every patch; per-thread state via TEB slots.
- Detector calibration (Peregrine, author-documented): ROP-style and MEM_IMAGE
  spoofing pass its call-stack check; it assumes exactly one trampoline frame
  (SKIP_FRAMES 2), so frame-less instrumentation shifts its view; rate-limiter
  budgets mean heavy legitimate traffic disables validation entirely.

### Measured on this lab box (cowtest, 2026-09-17)

- **SEC_IMAGE mapping is denied system-wide** (NtMapViewOfSection
  0xC0000022 even in-process, both kernel32 and winmm). Image-backed
  trampolines and image-backed self-mapping are therefore UNAVAILABLE here;
  v1 stays MEM_PRIVATE and the MEM_MAPPED-RX fallback (data section of a
  signed file) is the documented alternative (passes call-stack checks, fails
  VAD scans).
- **COW folklore falsified here**: after VirtualProtect(RW) + store + restore
  on a loaded kernel32 .text page, VirtualQuery still reports Type=MEM_IMAGE,
  Protect=RX, AllocationBase=image base, section name intact. Inline hooks
  inside loaded modules do NOT produce a MEM_PRIVATE tell on this build, and
  no new Protect/AllocationProtect mismatch appears after restore. Consistent
  with Peregrine; contradicts the widely repeated "written image pages report
  MEM_PRIVATE" claim.

## Research fold-in 6 — hook engines + stack spoofing survey (2026-09-17)

Survey verdict: no mainstream engine (MinHook, PolyHook2, Detours) addresses
stack-walk cleanliness; Detours PR #308 acknowledges the gap unmerged. We
therefore ship our own engine taking: MinHook's slot-allocator shape,
Detours' RW->RX protection lifecycle and thread-Rip fixup, and our own
unwind registration. Vendored public-domain HDE64 (third_party/hde, MinHook,
BSD-2-clause attribution kept; windows.h dependency removed for freestanding
safety) plus a restricted prologue probe that REFUSES RIP-relative operands,
branches, unsupported stack ops, and >16-byte steals (reasons are data).

Shipped this fold-in:
- [x] `hook_install`/`hook_remove`: shared trampoline region (RW, +/-1GB of
      target, 64 B slots) flipped RX once; E9 rel32 at target; whole
      instructions stolen per probe; thread suspend + parked-Rip remap;
      per-trampoline `RtlAddFunctionTable` with hand-built UNWIND_INFO
      (push-nonvol + alloc small/large forms; other prologues refused);
      FlushInstructionCache after every write.
- [x] `probe_caps` + `register_own_unwind` (fold-in 5) wired into entry.
- [x] `pivot_call`: pure-C stack pivot via RtlCaptureContext/RtlRestoreContext
      (no asm, no gadget hunt, no syscall), TEB.ArbitraryUserPointer as context
      slot; refuses when shadow stacks live/enforced (SetContextIpValidation).
- [x] Loader-mode contract: DllMain is a no-op (work under the loader lock
      crashed LoadLibrary); consumers kick off via exported NocrtManualEntry
      after load. `tools/loadtest` exercises this path.
- [x] `tools/cowtest`, `tools/loadtest` added; `tools/inspect.ps1` gained
      export/entry dumping.
- SKIP list adopted: sleep obfuscation families (Ekko/Foliage/Zilean/
      DeathSleep), module stomping, PEB-entry fabrication, HWBP as a general
      solution (4 slots/thread, DR visibility), VEH splicing, NtContinue
      teleportation as primary, CET WRSS spoofing, guard-page hooks vs unknown
      samples.
- REMAINS DETECTABLE (documented, blunt): hook bytes vs disk comparison
      (kernel readers unbeatable from user mode); our code executing in
      unbacked memory (ETW-TI attribution); manual mapping itself (VAD/PEB);
      kernel telemetry (ETW-TI, notify routines, ObRegisterCallbacks);
      gadget-shaped return addresses (image_rop rules); CET/HSP where
      enabled; stack truncation (null-terminated-stack rules); Intel PT
      (no production use found - folklore, but structurally fatal to
      unwind-metadata spoofing).

## Open questions / known-broken (2026-09-17, evidence attached)

1. **Manual-mapper flakiness (BLOCKER for repeatable live tests).** One full
   green end-to-end run exists (strings decrypted in-host, `ucrtbase!puts`
   called via export hash, `host_target` inline-hooked, CONTROL FLOW CHANGED).
   Later runs of the SAME binary fail silently: remote thread exits 1 with no
   stdout output and no entry-side-channel file (`entry.log`), while the host
   main thread stops printing at inject time. Merged images additionally fault
   inside mapped `.text` (WER: 0xC0000005 at base+0x1ECF..0x1F00); padded
   images never execute their entry. Exports/entry RVA verified correct;
   thread exit code 1 with zero side effects rules out a crash in our entry.
   Suspects not yet eliminated: environment state change after repeated
   APPCRASH/WER cycles, pool-thread scheduling under a redirected-stdout host,
   or an injector/host interaction not yet instrumented. Next step: reproduce
   under a kernel debugger or with `NtCreateThreadEx` + explicit stack and
   per-stage side-channel writes.
2. **Cross-process SEC_IMAGE mapping denied** (0xC0000022) on this system, so
   v1 ships MEM_PRIVATE private mapping. Roadmap: APC/self-map from inside the
   target (shellcode calling NtMapViewOfSection in target context) to obtain
   MEM_IMAGE without cross-process section mapping.
3. Section merges (`/MERGE:.pdata=.rdata /MERGE:.rdata=.text`) are green for
   disk-run images (demo/zero/patscan verified) but crash under the private
   mapper; disabled for the DLL pending root cause of (1).
4. Pad-up (`strip.exe <img> 65536`) verified to rewrite `SizeOfImage` and
   `.data` VirtualSize correctly, but padded images fail under the mapper;
   disabled for the DLL pending (1). `DllCharacteristics` plausibility
   (0x8160) is applied unconditionally and is harmless.
5. **Loader-mode kickoff crash (2026-09-18).** With the no-op DllMain fix,
   `LoadLibrary` succeeds and the exported kickoff runs; the entry side-channel
   file is written (`entry-ran`), but no stdout output appears and the process
   then dies (0xC0000005). Narrowed to: stdout path (`nocrt::out` -> api())
   silent in loader mode while raw CreateFileA/WriteFile works, then a fault
   after the side-channel block. Suspects: api()/GetStdHandle interaction under
   a redirected-stdout host, or the hook_install path in loader context.
   Next: per-stage side-channel writes around each out()/spawn/hook step.
