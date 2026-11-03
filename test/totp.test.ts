import assert from "node:assert/strict";
import { test } from "node:test";
import { hotp } from "../src/hotp.js";
import { MAX_WINDOW, matchTotp, totp, verifyTotp } from "../src/totp.js";

const SECRET = new Uint8Array(Buffer.from("12345678901234567890", "ascii"));
const T = 59_000; // RFC 6238 Appendix B, time step 1

test("totp is stable within a period and changes at the boundary", () => {
  const a = totp(SECRET, { now: 30_000 });
  assert.equal(totp(SECRET, { now: 59_999 }), a);
  assert.notEqual(totp(SECRET, { now: 60_000 }), a);
});

test("period and epoch shift the time step", () => {
  assert.equal(totp(SECRET, { now: 100_000, period: 60 }), hotp(SECRET, 1));
  assert.equal(totp(SECRET, { now: 130_000, epoch: 100 }), hotp(SECRET, 1));
});

test("totp validates period and clock inputs", () => {
  assert.throws(() => totp(SECRET, { period: 0 }), RangeError);
  assert.throws(() => totp(SECRET, { period: -30 }), RangeError);
  assert.throws(() => totp(SECRET, { period: Number.POSITIVE_INFINITY }), RangeError);
  assert.throws(() => totp(SECRET, { now: Number.NaN }), RangeError);
  assert.throws(() => totp(SECRET, { now: 5_000, epoch: 100 }), RangeError);
});

test("verifyTotp accepts the live step and rejects one outside the window", () => {
  assert.equal(verifyTotp("94287082", SECRET, { digits: 8, now: T }), true);
  assert.equal(verifyTotp("94287082", SECRET, { digits: 8, now: T + 60_000 }), false);
  assert.equal(verifyTotp("94287082", SECRET, { digits: 8, now: T + 60_000, window: 2 }), true);
});

test("window: 0 only accepts the current step", () => {
  const prev = hotp(SECRET, 0);
  assert.equal(verifyTotp(prev, SECRET, { now: T }), true); // default ±1
  assert.equal(verifyTotp(prev, SECRET, { now: T, window: 0 }), false);
});

test("matchTotp reports which time step matched, enabling replay protection", () => {
  const options = { now: 10 * 30_000 + 5_000 }; // step 10
  assert.equal(matchTotp(hotp(SECRET, 10), SECRET, options), 10n);
  assert.equal(matchTotp(hotp(SECRET, 9), SECRET, options), 9n);
  assert.equal(matchTotp(hotp(SECRET, 11), SECRET, options), 11n);
  assert.equal(matchTotp(hotp(SECRET, 12), SECRET, options), null);
});

test("never throws when the drift window reaches past the epoch", () => {
  assert.equal(verifyTotp(hotp(SECRET, 0), SECRET, { now: 0 }), true);
  assert.equal(verifyTotp("000000", SECRET, { now: 0 }), false);
  assert.equal(matchTotp(hotp(SECRET, 0), SECRET, { now: 0, window: MAX_WINDOW }), 0n);
});

test("malformed tokens return false rather than throwing", () => {
  assert.equal(verifyTotp("94287082", SECRET, { digits: 6, now: T }), false); // wrong length
  assert.equal(verifyTotp("9428708a", SECRET, { digits: 8, now: T }), false); // non-digit
  assert.equal(verifyTotp("９４２８７０８２", SECRET, { digits: 8, now: T }), false); // full-width digits
  assert.equal(verifyTotp(" 94287082", SECRET, { digits: 8, now: T }), false);
  assert.equal(verifyTotp("", SECRET, { now: T }), false);
});

test("window is validated and capped to bound CPU cost", () => {
  for (const window of [-1, 1.5, Number.NaN, MAX_WINDOW + 1]) {
    assert.throws(() => verifyTotp("94287082", SECRET, { digits: 8, window }), RangeError, String(window));
  }
  assert.doesNotThrow(() => verifyTotp("94287082", SECRET, { digits: 8, now: T, window: MAX_WINDOW }));
});
