<!-- SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Memory Safety Direction

TurboVAS is incrementally reducing reliance on memory-unsafe implementation.
The project inherits substantial C code from OpenVAS and the wider Greenbone
Community Edition stack, including security-sensitive scanner, protocol,
parsing, credential, report, and service functionality.

Memory safety is one part of the broader TurboVAS security posture. It does not
replace authentication, authorization, input validation, scanner safety,
cryptographic review, deployment hardening, dependency management, or secure
operational defaults.

## Rationale

Memory-safe languages prevent classes of defects such as buffer overflows,
use-after-free, invalid lifetime use, and many data races by default. Static
analysis, fuzzing, compiler hardening, sanitizers, and careful review remain
valuable for C, but they cannot provide the same language-enforced guarantees.

TurboVAS's direction is informed by secure-by-design guidance, including the
NSA and CISA publication [*Memory Safe Languages: Reducing Vulnerabilities in
Modern Software Development*](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4223298/nsa-and-cisa-release-csi-highlighting-importance-of-memory-safe-languages-in-so/).
That guidance recommends incremental adoption, prioritizing new and high-risk
components, defining robust interoperability boundaries, and continuing to
harden legacy code where immediate migration is impractical. This reference
does not imply endorsement of TurboVAS by NSA, CISA, or the United States
Government.

## Development Policy

- New security-sensitive backend functionality is Rust-first.
- New C requires a concrete technical justification. A narrow change to an
  existing C subsystem may be safer than introducing a premature cross-language
  boundary or broad rewrite.
- Functionality that TurboVAS does not retain should be deleted rather than
  translated.
- Migration is incremental and risk-ranked. It must preserve required behavior,
  scanner fidelity, performance, interfaces, license/provenance obligations,
  and operational evidence.
- Rust `unsafe` and foreign-function interfaces are explicit security
  boundaries. Keep them small, documented, and covered by focused tests.
- Automated C-to-Rust translation may support exploration, but generated code
  is not accepted as finished production code without characterization,
  review, validation, and cleanup.

Rust is the default systems language for this direction because it combines
memory safety without garbage collection, strong concurrency guarantees,
predictable performance, and practical C interoperability. This is an
engineering choice for TurboVAS, not a claim that Rust is the only suitable
memory-safe language.

## Retained C

The existence of C is neither proof of a vulnerability nor proof of safety.
Retained memory-unsafe code must eventually have an explicit disposition:

1. remove it when its functionality is unnecessary;
2. isolate and harden it when retention is currently justified; or
3. replace it incrementally through a validated boundary.

Until removal or replacement, relevant controls include:

- compiler warnings and hardening options;
- CodeQL and other focused static analysis;
- AddressSanitizer, UndefinedBehaviorSanitizer, and equivalent dynamic checks
  where the component can be exercised meaningfully;
- fuzzing and malformed-input tests at parser and protocol boundaries;
- focused allocation, bounds, lifetime, cleanup, and error-path tests;
- least-privilege service and filesystem containment;
- explicit review of temporary files, subprocesses, credentials, and network
  exposure.

The durable commitments and staged evidence model for those controls are
defined in [Retained C Hardening Strategy](C_HARDENING.md).

Suppressing a warning or excluding a deliberately retained compatibility path
from a generic query is not the same as removing the underlying risk. The
reason for retention must remain visible.

## Prioritization

Migration priority follows exposure and consequence rather than raw line count:

1. network-facing services, protocol handlers, and parsers;
2. authentication, credentials, secrets, subprocesses, and temporary files;
3. report, XML, feed, file, and target-controlled input processing;
4. scanner execution, concurrent lifecycle, queue, and result-state handling;
5. complex ownership, allocation, and cleanup paths;
6. lower-exposure utility code.

The native HTTP/JSON API is part of this strategy. It moves new service and
validation logic into Rust, creates typed boundaries around retained systems,
and allows obsolete GMP/XML, Python, and C-owned workflow surface to be removed
instead of maintained indefinitely.

## Validation And Progress

Memory-safety migration is complete only when the replacement is at least as
correct, secure, observable, and operationally effective as the retained
behavior. Depending on the component, evidence may include:

- characterization tests before replacement;
- Rust and retained-language unit/integration tests;
- sanitizer and fuzzing results;
- static-analysis and security-policy checks;
- ABI/FFI contract tests;
- runtime scanner and browser evidence;
- before/after performance measurements;
- proof that the superseded code and callers were removed.

Useful progress measures include externally influenced inputs still parsed in
C, exposed `unsafe`/FFI boundaries, sanitizer and fuzz-target coverage, and open
memory-safety findings. C line count alone is not a security metric.

Run:

```sh
just rust-migration-state --json
just security-policy-check --json
just quality-gate --json
```

These commands provide engineering evidence; they do not certify that the
system is free of memory-safety or other security defects.
