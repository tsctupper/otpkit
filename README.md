# otpkit

**Zero-dependency, RFC-verified HOTP & TOTP (2FA) for Node.js and TypeScript.**

[![CI](https://github.com/tsctupper/otpkit/actions/workflows/ci.yml/badge.svg)](https://github.com/tsctupper/otpkit/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@tsctupper/otpkit)](https://www.npmjs.com/package/@tsctupper/otpkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Node](https://img.shields.io/badge/node-%3E%3D18-blue)
![Types](https://img.shields.io/badge/types-included-blue)

The one-time-password codes behind Google Authenticator, Authy, and every "enter your 6-digit code" screen — implemented straight from the RFCs, with **no runtime dependencies** and a test suite that asserts **byte-for-byte compliance with the official specification test vectors**.

- HOTP (RFC 4226) and TOTP (RFC 6238), SHA-1 / SHA-256 / SHA-512
- Base32 (RFC 4648) secrets — the format authenticator apps use
- `otpauth://` provisioning URIs for QR-code enrollment
- Constant-time verification with a bounded clock-drift window, plus `matchTotp` for replay protection
- Zero dependencies, ESM, first-class TypeScript types
- Verified against the RFC 4226 / 6238 / 4648 test vectors in CI, with 100% line and branch coverage

## Install

```sh
npm install @tsctupper/otpkit
```

Node >= 18. Ships ESM + `.d.ts` types.

## Quick start

### Enroll a user

```ts
import { generateSecret, otpauthURL, base32Encode } from "@tsctupper/otpkit";

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
import { verifyTotp, base32Decode } from "@tsctupper/otpkit";

const secret = base32Decode(storedBase32Secret);
const ok = verifyTotp(userSubmittedCode, secret); // ±1 step of drift by default

if (!ok) throw new Error("Invalid code");
```

### Reject replayed codes

A valid code stays valid for its whole window, so an attacker who sees one can reuse it. `matchTotp` tells you _which_ time step matched, so you can refuse anything you have already accepted:

```ts
import { matchTotp } from "@tsctupper/otpkit";

const step = matchTotp(userSubmittedCode, secret);
if (step === null || step <= user.lastTotpStep) throw new Error("Invalid code");

user.lastTotpStep = step; // persist per user (e.g. in your database)
```

### Generate a code (client side, tests, or debugging)

```ts
import { totp, hotp } from "@tsctupper/otpkit";

totp(secret); // current 6-digit TOTP
totp(secret, { digits: 8, algorithm: "SHA256", period: 60 });
hotp(secret, 42); // counter-based (RFC 4226)
```

## Try the complete second-factor flow

The [runnable local example](https://github.com/tsctupper/otpkit/tree/main/examples/two-factor)
uses the published npm package and a real authenticator app. It walks through
enrollment, confirmation, a sign-in challenge, rejected codes, replay protection
and attempt limits, with no server or database setup.

```sh
git clone https://github.com/tsctupper/otpkit.git
cd otpkit/examples/two-factor
npm ci
npm start
```

This demonstrates the second factor, not a complete login system. Its one demo
account lives in memory. The example explains the production requirements for
authenticated account identity, encrypted secret storage, atomic replay protection,
shared rate limits and recovery. No account identifier supplied by a caller is
used to authorize enrollment or verification.

## API

| Function                           | Purpose                                                                                                   |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `hotp(secret, counter, opts?)`     | RFC 4226 counter-based OTP.                                                                               |
| `totp(secret, opts?)`              | RFC 6238 time-based OTP for now (or an injected `now`).                                                   |
| `verifyTotp(token, secret, opts?)` | Constant-time check across a drift `window` (default ±1, max `MAX_WINDOW` = 100). Returns `boolean`.      |
| `matchTotp(token, secret, opts?)`  | Like `verifyTotp`, but returns the matched time-step (`bigint`) or `null` — use it for replay protection. |
| `generateSecret(bytes?)`           | CSPRNG secret, default 20 bytes / 160 bits.                                                               |
| `otpauthURL(secret, params)`       | `otpauth://totp/...` enrollment URI.                                                                      |
| `base32Encode` / `base32Decode`    | RFC 4648 Base32, tolerant decode.                                                                         |

`secret` is always **raw bytes** (`Uint8Array`) — decode Base32 text first. Options: `digits` (6–8, default 6), `algorithm` (`"SHA1"` default), `period` (30s), `window`, `now`, `epoch`. Full types are bundled.

Invalid configuration (out-of-range digits, non-positive period, a `window` outside 0–100, an empty secret or label) throws a `RangeError`; a malformed or wrong token never throws — `verifyTotp` just returns `false`.

## Standards & verification

Correctness isn't asserted by hand — the test suite runs the specifications' own vectors:

| Standard                                           | Covers | Vectors checked                      |
| -------------------------------------------------- | ------ | ------------------------------------ |
| [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) | HOTP   | Appendix D (counters 0–9)            |
| [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) | TOTP   | Appendix B (SHA-1/256/512, 8 digits) |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Base32 | §10 canonical vectors                |

Run them yourself: `npm test`.

## Design notes

- **Only `node:crypto`.** HMAC and `timingSafeEqual` come from Node's standard library, so there is no dependency tree to audit and nothing for a supply-chain attack to land in.
- **Secrets are raw bytes.** Functions take a `Uint8Array`, not a string, so the Base32-versus-raw-bytes mix-up that breaks many TOTP integrations can't happen silently. Base32 is a separate, explicit step.
- **`bigint` counters.** The RFC 4226 counter is 64 bits wide. JavaScript numbers lose precision past 2^53, so counters are `bigint` internally and anything above 2^64 − 1 is rejected rather than wrapped.
- **`matchTotp` returns the step, not a boolean.** Replay protection needs to know _which_ step was accepted. Returning it keeps the library stateless while making the safe pattern the easy one. `verifyTotp` is a thin wrapper for when you don't need it.
- **Bounded work on untrusted input.** Each step in the drift window costs one HMAC, so the window is capped at 100. Malformed tokens return `false` instead of throwing, so bad input can't be used to crash a login path.
- **Scope.** It generates and verifies codes and builds the enrollment URI. It does not render QR codes, store secrets or rate-limit; those belong to your application, and the runnable example above demonstrates the application boundary.

## Security notes

- **Verification is constant-time.** Every candidate step is compared with `crypto.timingSafeEqual` and the loop never short-circuits, so neither the result nor the matching step leaks through timing.
- **Secrets are ≥ 160 bits** by default, per RFC 4226 §4. Store them encrypted at rest; never log them.
- **Keep the drift `window` small** (±1 is usually right). A larger window is more forgiving of clock skew but widens the guess surface. It is capped at 100 steps so untrusted input can't force unbounded HMAC work.
- This library generates and verifies codes. **Replay protection** and **rate-limiting failed attempts** are the caller's responsibility — see `matchTotp` above. A 6-digit code has only a million possibilities, so always throttle.
- Found a vulnerability? See [SECURITY.md](./SECURITY.md).

## Development

```sh
npm ci
npm run check      # typecheck, lint, format check, tests
npm run coverage   # line/branch coverage (held at 100%)
npm run build      # emit dist/ (ESM + .d.ts)
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) and the [CHANGELOG](./CHANGELOG.md).

## License

[MIT](./LICENSE) © Tyler Tupper
