# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] — 2026-11-03

### Changed

- The release workflow now stages the npm publish (`npm stage publish`) instead
  of publishing directly, because npm is retiring two-factor-bypass tokens. A
  maintainer approves the staged release on npmjs.com. No library changes.

## [1.1.0] — 2026-11-03

### Added

- `matchTotp` returns the matched time-step counter (or `null`), making replay
  protection straightforward (RFC 6238 §5.2). `verifyTotp` is now built on it.
- `MAX_WINDOW` export. A `window` above 100 now throws `RangeError`, bounding
  the HMAC work that untrusted input can request.

### Fixed

- `verifyTotp` no longer throws when the drift window reaches past the epoch
  (e.g. verifying within the first period with `window: 1`); pre-epoch steps
  are skipped and verification returns `false` as expected.
- `period` and `now` are validated up front — `period: 0` now throws a clear
  `RangeError` instead of a confusing BigInt conversion error.
- `digits` is restricted to 6–8 per RFC 4226 §5.3; dynamic truncation yields at
  most 31 bits, so 9–10 digit codes could never cover their full range.
- `otpauthURL` percent-encodes issuer and label separately with a literal `:`
  separator, matching the Key URI Format's canonical examples.
- Empty secrets and non-digit tokens are rejected explicitly.
- `otpauthURL` encodes spaces as `%20` instead of `+` in query values (issuer),
  and validates `label`, `digits` and `period`.
- `hotp` rejects counters above 2^64 − 1 instead of silently wrapping.
- `base32Decode` rejects `=` anywhere but the end, and trims trailing padding in
  linear time (a regex here was quadratic on long runs of `=`).

### Changed

- CI now tests every supported Node line: 18, 20, 22, and 24.
- Strict type-checked ESLint, Prettier, `noUncheckedIndexedAccess`, and a
  type-checked test suite split per module, with 100% line and branch coverage.
- CI gains a lint/format/coverage job and a packed-install smoke test.
- Added `SECURITY.md`, `CONTRIBUTING.md`, issue and PR templates, Dependabot,
  CodeQL, and an npm release workflow with provenance.

## [1.0.0] — 2026-07-16

### Added

- `hotp` — RFC 4226 HMAC-based OTP (SHA-1/256/512, configurable digits).
- `totp` / `verifyTotp` — RFC 6238 time-based OTP with constant-time,
  drift-window verification.
- `generateSecret` and `otpauthURL` for enrollment (QR / manual key).
- `base32Encode` / `base32Decode` — RFC 4648 Base32, tolerant decoding.
- Test suite pinned to the RFC 4226, 6238, and 4648 official vectors.

[Unreleased]: https://github.com/tsctupper/otpkit/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/tsctupper/otpkit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/tsctupper/otpkit/releases/tag/v1.0.0
