# Security Policy

otpkit handles authentication secrets, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately via
[GitHub Security Advisories](https://github.com/tsctupper/otpkit/security/advisories/new).
You can expect an acknowledgement within a few days and a fix or mitigation plan soon after.

## Supported versions

Only the latest `1.x` release receives security fixes.

## Design notes relevant to reviewers

- Code comparison uses `crypto.timingSafeEqual` and evaluates every window step (no early exit).
- Secrets come from `crypto.randomBytes`; `generateSecret` refuses fewer than 128 bits.
- `verifyTotp` bounds its work (`window` ≤ `MAX_WINDOW`) so untrusted input can't cause unbounded HMAC computation.
- Replay protection and brute-force rate limiting are deliberately left to the application; `matchTotp` returns the matched time step to make the former straightforward.
- There are no runtime dependencies, so no transitive supply-chain surface.
