# Try a complete second-factor flow

This local command-line example uses the **published npm package**, not an import
from this repository's source. It demonstrates one temporary account: enrollment,
confirmation, a sign-in challenge, rejected codes, replay protection and throttling.
You can use a real authenticator app without setting up a server or database.

## Run

With Node.js 18 or newer, from the repository root:

```sh
cd examples/two-factor
npm ci
npm start
```

1. Choose **1 Enroll**. In your authenticator, add a new time-based entry with the
   displayed manual setup key. Use SHA1, six digits and a 30-second period. The
   enrollment URI is provided for applications that can import one; no QR-code
   renderer is included.
2. Choose **2 Confirm enrollment** and enter the current authenticator code within
   five minutes. The account is not enrolled until that code succeeds.
3. **Wait for the code to change**, then choose **3 Sign-in challenge**. The code
   used for confirmation has already been consumed and cannot sign in again.
4. Try the accepted code again: it is rejected. Try five invalid codes: challenges
   are locked for 30 seconds. Restarting enrollment does not clear the limit.
5. Choose **4 Exit**. Delete the demo entry from your authenticator afterward.

The manual key and URI contain the same secret. They are intentionally shown for
local setup; do not share them, use a recorded/shared terminal, or reuse a real
account secret. Typed codes are visible. The example makes no network requests
after installation, writes no account data to disk, and loses state on exit.
Restarting the process creates a fresh demo, including fresh rate-limit state.

## Where otpkit ends and the application begins

| otpkit supplies                    | This example supplies                              |
| ---------------------------------- | -------------------------------------------------- |
| Random secrets and enrollment URIs | Pending enrollment with five-minute expiry         |
| Base32 setup keys                  | Activation only after a valid confirmation code    |
| Matching the code to a time step   | Consuming steps and rejecting replayed/older codes |
| A bounded clock-drift window       | Five-failure limit and a 30-second demo lock       |

The window is ±1 step. Verification and step consumption happen synchronously
in one process, so a second call cannot reuse an accepted step. No user-supplied
account identifier is trusted: this process contains exactly one demo account.

## Before adapting this to a real application

This is the **second factor**, not a complete login system or production service.
There is no password check, identity/session management, recovery or account store.

- Authenticate the account before enrollment or changes, and tie sign-in
  verification to a short-lived challenge created after the first factor passes.
  Derive account identity from that session/challenge, never a caller's `userId`.
- Store secrets encrypted at rest with managed keys. Keep enrollment secrets out
  of logs, analytics and URLs that might be captured by access logs. Use HTTPS and
  appropriate request protections for a web implementation.
- Persist the last accepted step and rate-limit state. Atomically accept a code
  only if its step is greater than the stored step; separate read/write operations
  allow concurrent requests to reuse a code. Limits must work across workers and
  restarts. Choose an appropriate lock policy rather than copying the short demo
  duration unchanged.
- Design recovery, factor replacement and reauthentication before launch. Those
  flows must not bypass the protection added by two-factor authentication.
- Authenticator codes can be phished. For higher-assurance access, evaluate
  phishing-resistant passkeys/security keys; TOTP alone is not that protection.

## Verify

```sh
npm test
```

Tests use an injected clock and synthetic secrets, with no sleeps or external
services. CI runs the flow against the locked published package on Node 18, 20,
22 and 24. To try an unpublished local package, build and pack the library at the
repository root, then install that tarball here with `npm install --no-save
--package-lock=false /absolute/path/to/package.tgz` and rerun the tests. Restore
the published dependency afterward with `npm ci`.
