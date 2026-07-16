# otpkit

**Zero-dependency, RFC-verified HOTP & TOTP (2FA) for Node.js and TypeScript.**

[![CI](https://github.com/tsctupper/otpkit/actions/workflows/ci.yml/badge.svg)](https://github.com/tsctupper/otpkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Node](https://img.shields.io/badge/node-%3E%3D18-blue)
![Types](https://img.shields.io/badge/types-included-blue)

The one-time-password codes behind Google Authenticator, Authy, and every "enter your 6-digit code" screen — implemented straight from the RFCs, with **no runtime dependencies** and a test suite that asserts **byte-for-byte compliance with the official specification test vectors**.

- HOTP (RFC 4226) and TOTP (RFC 6238), SHA-1 / SHA-256 / SHA-512
- Base32 (RFC 4648) secrets — the format authenticator apps use
- `otpauth://` provisioning URIs for QR-code enrollment
- Constant-time verification with a configurable clock-drift window
- Zero dependencies, ESM, first-class TypeScript types
- Verified against the RFC 4226 / 6238 / 4648 test vectors in CI

## Install

```sh
npm install otpkit
```

Node >= 18. Ships ESM + `.d.ts` types.

## Quick start

### Enroll a user

```ts
import { generateSecret, otpauthURL, base32Encode } from "otpkit";

const secret = generateSecret(); // 20 random bytes (160 bits)
const uri = otpauthURL(secret, {
  label: "alice@example.com",
  issuer: "Acme",
});

// Render `uri` as a QR code for the user to scan, and store `secret` (encrypted).
// The manual-entry key is the Base32 form:
const manualKey = base32Encode(secret);
```

### Verify a code

```ts
import { verifyTotp, base32Decode } from "otpkit";

const secret = base32Decode(storedBase32Secret);
const ok = verifyTotp(userSubmittedCode, secret); // ±1 step of drift by default

if (!ok) throw new Error("Invalid code");
```

### Generate a code (client side, tests, or debugging)

```ts
import { totp, hotp } from "otpkit";

totp(secret); // current 6-digit TOTP
totp(secret, { digits: 8, algorithm: "SHA256", period: 60 });
hotp(secret, 42); // counter-based (RFC 4226)
```

## API

| Function | Purpose |
| --- | --- |
| `hotp(secret, counter, opts?)` | RFC 4226 counter-based OTP. |
| `totp(secret, opts?)` | RFC 6238 time-based OTP for now (or an injected `now`). |
| `verifyTotp(token, secret, opts?)` | Constant-time check across a drift `window` (default ±1). |
| `generateSecret(bytes?)` | CSPRNG secret, default 20 bytes / 160 bits. |
| `otpauthURL(secret, params)` | `otpauth://totp/...` enrollment URI. |
| `base32Encode` / `base32Decode` | RFC 4648 Base32, tolerant decode. |

`secret` is always **raw bytes** (`Uint8Array`) — decode Base32 text first. Options: `digits` (default 6), `algorithm` (`"SHA1"` default), `period` (30s), `window`, `now`, `epoch`. Full types are bundled.

## Standards & verification

Correctness isn't asserted by hand — the test suite runs the specifications' own vectors:

| Standard | Covers | Vectors checked |
| --- | --- | --- |
| [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) | HOTP | Appendix D (counters 0–9) |
| [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) | TOTP | Appendix B (SHA-1/256/512, 8 digits) |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Base32 | §10 canonical vectors |

Run them yourself: `npm test`.

## Security notes

- **Verification is constant-time.** Every candidate step is compared with `crypto.timingSafeEqual` and the loop never short-circuits, so neither the result nor the matching step leaks through timing.
- **Secrets are ≥ 160 bits** by default, per RFC 4226 §4. Store them encrypted at rest; never log them.
- **Keep the drift `window` small** (±1 is usually right). A larger window is more forgiving of clock skew but widens the guess surface.
- This library generates and verifies codes; **replay protection** (rejecting an already-used code within its window) is the caller's responsibility.

## License

[MIT](./LICENSE) © Tyler Tupper
