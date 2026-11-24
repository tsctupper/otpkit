import { base32Encode, generateSecret, matchTotp, otpauthURL } from "@tsctupper/otpkit";

const MAX_FAILURES = 5;
const LOCK_MS = 30_000;
const ENROLLMENT_MS = 5 * 60_000;

// One account, one process. Methods are synchronous: checking a code and
// consuming its step happen together. A database-backed app needs an atomic
// conditional update, not a separate read followed by a write.
export function createDemoAccount({ now = Date.now } = {}) {
  let pending;
  let active;
  let lastStep = -1n;
  let failures = 0;
  let lockedUntil = 0;

  function lockStatus(time) {
    if (time < lockedUntil) {
      return { ok: false, reason: "locked", retryAfter: Math.ceil((lockedUntil - time) / 1000) };
    }
    if (lockedUntil) {
      lockedUntil = 0;
      failures = 0;
    }
    return null;
  }

  function reject(time) {
    failures += 1;
    if (failures >= MAX_FAILURES) {
      lockedUntil = time + LOCK_MS;
      return lockStatus(time);
    }
    return { ok: false, reason: "invalid-code" };
  }

  function verify(code, secret, time) {
    // Untrusted input is checked before it reaches the library's string API.
    if (typeof code !== "string" || !/^[0-9]{6}$/.test(code)) return reject(time);
    const step = matchTotp(code, secret, { now: time, window: 1 });
    if (step === null || step <= lastStep) return reject(time);
    lastStep = step;
    failures = 0;
    return { ok: true };
  }

  return {
    enroll() {
      const time = now();
      const locked = lockStatus(time);
      if (locked) return locked;
      if (active) return { ok: false, reason: "already-enrolled" };
      // Starting over does not clear failures or reset an existing deadline.
      if (!pending || time >= pending.expires) {
        pending = { secret: generateSecret(), expires: time + ENROLLMENT_MS };
      }
      return {
        ok: true,
        manualKey: base32Encode(pending.secret).replace(/=+$/, ""),
        uri: otpauthURL(pending.secret, { label: "local-demo", issuer: "otpkit example" }),
      };
    },

    confirm(code) {
      const time = now();
      const locked = lockStatus(time);
      if (locked) return locked;
      if (active) return { ok: false, reason: "already-enrolled" };
      if (!pending) return { ok: false, reason: "not-started" };
      if (time >= pending.expires) {
        pending = undefined;
        return { ok: false, reason: "enrollment-expired" };
      }
      const result = verify(code, pending.secret, time);
      if (result.ok) {
        active = pending.secret;
        pending = undefined;
      }
      return result;
    },

    signIn(code) {
      const time = now();
      const locked = lockStatus(time);
      if (locked) return locked;
      if (!active) return { ok: false, reason: "not-enrolled" };
      return verify(code, active, time);
    },
  };
}
