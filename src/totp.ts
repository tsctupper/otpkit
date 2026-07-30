import { timingSafeEqual } from "node:crypto";
import { hotp, type HotpOptions } from "./hotp.js";

export interface TotpOptions extends HotpOptions {
  /** Time step in seconds (default 30). */
  period?: number;
  /** Unix epoch offset T0 in seconds (default 0). */
  epoch?: number;
  /** Unix time in milliseconds (default `Date.now()`). Inject for deterministic tests. */
  now?: number;
}

/** Time-step index for a moment — RFC 6238 §4.2. */
function counterFor(options: TotpOptions): bigint {
  const period = options.period ?? 30;
  const epoch = options.epoch ?? 0;
  const nowMs = options.now ?? Date.now();
  if (!Number.isFinite(period) || period <= 0) {
    throw new RangeError("period must be a positive number of seconds");
  }
  if (!Number.isFinite(nowMs)) throw new RangeError("now must be a finite Unix time in milliseconds");
  const seconds = Math.floor(nowMs / 1000) - epoch;
  if (seconds < 0) throw new RangeError("now is before the epoch (T0)");
  return BigInt(Math.floor(seconds / period));
}

/** RFC 6238 time-based OTP for the current (or supplied) moment. */
export function totp(secret: Uint8Array, options: TotpOptions = {}): string {
  return hotp(secret, counterFor(options), options);
}

export interface VerifyOptions extends TotpOptions {
  /** Clock-drift steps accepted on either side (default 1 = ±one period). */
  window?: number;
}

/**
 * Verify a token against a drift window in constant time.
 *
 * Every candidate step is checked (no early return) and each comparison uses
 * `timingSafeEqual`, so neither *whether* nor *which* step matched leaks through
 * timing.
 */
export function verifyTotp(token: string, secret: Uint8Array, options: VerifyOptions = {}): boolean {
  const window = options.window ?? 1;
  if (!Number.isInteger(window) || window < 0) {
    throw new RangeError("window must be a non-negative integer");
  }
  const digits = options.digits ?? 6;
  if (token.length !== digits || !/^[0-9]+$/.test(token)) return false;

  const expected = Buffer.from(token, "ascii");
  const center = counterFor(options);
  let matched = false;
  for (let e = -window; e <= window; e++) {
    const step = center + BigInt(e);
    // Steps before the epoch don't exist — skip rather than throw, so a
    // drift window that reaches past T0 can never crash verification.
    if (step < 0n) continue;
    const candidate = Buffer.from(hotp(secret, step, options), "ascii");
    if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) {
      matched = true;
    }
  }
  return matched;
}
