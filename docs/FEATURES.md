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

## Verification log

- 2026-09-18: build OK; imports `KERNEL32.dll` only; demo self-tests pass;
  xstr ciphertext differs per site; plaintext `polymorphic` absent from exe;
  naive literal `freestanding` present (documents the opt-in gotcha).
