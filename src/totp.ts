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
  const steps = Math.floor(Math.floor(nowMs / 1000) - epoch) / period;
  return BigInt(Math.floor(steps));
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
  if (token.length !== digits) return false;

  const expected = Buffer.from(token, "ascii");
  const center = counterFor(options);
  let matched = false;
  for (let e = -window; e <= window; e++) {
    const candidate = Buffer.from(hotp(secret, center + BigInt(e), options), "ascii");
    if (candidate.length === expected.length && timingSafeEqual(candidate, expected)) {
      matched = true;
    }
  }
  return matched;
}
