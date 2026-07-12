<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Retained C Hardening Strategy

TurboVAS inherits security-sensitive C from OpenVAS and the wider Greenbone
Community Edition stack. The project removes inherited functionality it does
not need, uses Rust by default for new security-sensitive backend work, and
incrementally replaces high-risk C where a validated boundary makes that
safer. C that remains must be defended and tested deliberately.

Compiler flags, analysis tools, and sanitizers reduce risk; they do not make C
memory-safe and do not prove that TurboVAS is secure.

This strategy is guided by OpenSSF compiler-hardening guidance; official GCC,
Clang, CMake, and GitHub CodeQL documentation; the SEI CERT C Coding Standard;
NIST's Secure Software Development Framework; and NSA/CISA memory-safe-language
guidance. These sources inform TurboVAS engineering choices but do not imply
endorsement, certification, or complete compliance with any standard.

## Commitments

TurboVAS will:

1. remove unnecessary inherited C rather than harden unused functionality;
2. prioritize retained C by exposure and consequence, not source-line count;
3. build production-style C with supported compiler, linker, and platform
   protections;
4. inspect produced binaries instead of inferring protection from configured
   flags;
5. exercise suitable component tests under memory- and undefined-behavior
   instrumentation;
6. use build-aware static analysis alongside broad source analysis;
7. keep warning suppressions and analysis exclusions narrow, justified, and
   separate from new TurboVAS code;
8. record unsupported, inapplicable, and inconclusive protections honestly;
9. preserve ordinary developer speed by separating routine, instrumented, and
   deep-analysis builds; and
10. replace retained C when hardening cannot reduce its risk enough.

## Build And Analysis Profiles

The intended C workflow has independent build trees and purposes:

- **Hardened:** optimized, debuggable production-style binaries with supported
  Fortify, strong stack protection, stack-clash protection, RELRO/NOW,
  non-executable stack, PIE or PIC as appropriate, and architecture-specific
  control-flow protection.
- **ASan/UBSan:** non-production test binaries with AddressSanitizer and
  UndefinedBehaviorSanitizer, frame pointers, symbols, and fail-fast runtime
  behavior.
- **Analysis:** exact compilation databases for focused Clang-Tidy and GCC
  analyzer runs, plus build-aware CodeQL where practical.

Flags are feature-tested and applied by target type. Executables, shared
libraries, PostgreSQL modules, and imported compatibility code do not receive
one indiscriminate linker configuration. Sanitizer runtimes are never part of
production artifacts.

## Evidence

A hardened configuration is not sufficient evidence. The project intends to
verify final ELF artifacts for applicable properties such as:

- position-independent executables;
- non-executable stack;
- full RELRO and immediate binding;
- effective stack protection and Fortify use;
- architecture-specific protection notes;
- absence of unexpected text relocations and executable-stack requests.

Results must distinguish `present`, `missing`, `unsupported`,
`not_applicable`, and `unknown`. Unknown is not success.

Sanitizer and analyzer output is bug-finding evidence, not certification. Tool
findings are triaged by reachability, attacker or target influence, affected
privilege, and consequence. Total warning count is not a security metric.

## Incremental Adoption

TurboVAS is a brownfield codebase. Hardening is introduced in bounded steps:

1. inventory the current toolchain, C build baseline, produced ELF artifacts,
   and existing protections;
2. add an explicit hardened profile and verify its final artifacts;
3. run feasible component and parser tests under ASan and UBSan;
4. export compilation databases and establish non-blocking analysis baselines;
5. add build-aware CodeQL coverage for the C that is actually compiled;
6. narrow inherited suppressions, beginning with the broad `openvas-smb`
   compatibility boundary;
7. make stable, high-confidence checks blocking only after their baseline and
   failure semantics are understood.

Externally reachable services, protocol and file parsers, credentials and
secrets, subprocesses, temporary files, target-controlled scanner input,
process lifecycle, IPC, allocation arithmetic, and C/Rust boundaries receive
priority.

## Current Status

The required C build baseline is `gvm-libs`, `openvas-smb`,
`openvas-scanner`, `pg-gvm`, `gvmd`, and `gsad`. Existing components already
apply some hardening, but coverage varies by component and build type.

`just build-c-services` is the current required compile check. It does not by
itself prove that every produced binary is hardened. Dedicated hardened,
sanitizer, analysis, and artifact-verification profiles are planned work and
must not be represented as implemented until their commands and evidence are
available.

See [Memory Safety Direction](MEMORY_SAFETY.md) for the broader remove, retain,
or replace policy and [Minimum Validation Standards](VALIDATION_STANDARDS.md)
for current change-class gates.

## References

### Technical Implementation Guidance

- [OpenSSF Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C%2B%2B.html)
- [GCC instrumentation and hardening options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- [Clang AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html)
- [Clang UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [GCC static analyzer options](https://gcc.gnu.org/onlinedocs/gcc/Static-Analyzer-Options.html)
- [Clang-Tidy](https://clang.llvm.org/extra/clang-tidy/)
- [CMake compilation database support](https://cmake.org/cmake/help/latest/variable/CMAKE_EXPORT_COMPILE_COMMANDS.html)
- [GitHub CodeQL for compiled languages](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-for-compiled-languages)

### Secure Development Strategy

- [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
- [SEI CERT C Coding Standard](https://www.sei.cmu.edu/library/sei-cert-c-coding-standard-rules-for-developing-safe-reliable-and-secure-systems-2016-edition/)
- [NSA/CISA memory-safe-languages guidance](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4223298/nsa-and-cisa-release-csi-highlighting-importance-of-memory-safe-languages-in-so/)
