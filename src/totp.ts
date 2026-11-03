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

/** Largest accepted drift window. Each step costs one HMAC, so this bounds CPU work. */
export const MAX_WINDOW = 100;

export interface VerifyOptions extends TotpOptions {
  /** Clock-drift steps accepted on either side (default 1 = ±one period, max {@link MAX_WINDOW}). */
  window?: number;
}

/**
 * Check a token against a drift window in constant time and report *which*
 * time step matched.
 *
 * Returns the matching RFC 6238 time-step counter, or `null` if nothing in the
 * window matched. Persist the counter per user and reject any token whose
 * counter is `<=` the last accepted one — that is replay protection
 * (RFC 6238 §5.2).
 *
 * Every candidate step is checked (no early return) and each comparison uses
 * `timingSafeEqual`, so neither *whether* nor *which* step matched leaks
 * through timing. Malformed tokens return `null`; invalid configuration throws.
 */
export function matchTotp(token: string, secret: Uint8Array, options: VerifyOptions = {}): bigint | null {
  const window = options.window ?? 1;
  if (!Number.isInteger(window) || window < 0 || window > MAX_WINDOW) {
    throw new RangeError(`window must be an integer between 0 and ${MAX_WINDOW}`);
  }
  const digits = options.digits ?? 6;
  if (token.length !== digits || !/^[0-9]+$/.test(token)) return null;

  const expected = Buffer.from(token, "ascii");
  const center = counterFor(options);
  let matched: bigint | null = null;
  for (let e = -window; e <= window; e++) {
    const step = center + BigInt(e);
    // Steps before the epoch don't exist — skip rather than throw, so a
    // drift window that reaches past T0 can never crash verification.
    if (step < 0n) continue;
    const candidate = Buffer.from(hotp(secret, step, options), "ascii");
    if (timingSafeEqual(candidate, expected)) matched = step;
  }
  return matched;
}

/** Verify a token against a drift window in constant time. See {@link matchTotp}. */
export function verifyTotp(token: string, secret: Uint8Array, options: VerifyOptions = {}): boolean {
  return matchTotp(token, secret, options) !== null;
}
