# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-16

### Added
- `hotp` — RFC 4226 HMAC-based OTP (SHA-1/256/512, configurable digits).
- `totp` / `verifyTotp` — RFC 6238 time-based OTP with constant-time,
  drift-window verification.
- `generateSecret` and `otpauthURL` for enrollment (QR / manual key).
- `base32Encode` / `base32Decode` — RFC 4648 Base32, tolerant decoding.
- Test suite pinned to the RFC 4226, 6238, and 4648 official vectors.

[1.0.0]: https://github.com/tsctupper/otpkit/releases/tag/v1.0.0
