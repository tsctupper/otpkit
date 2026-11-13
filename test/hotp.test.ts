import assert from "node:assert/strict";
import { test } from "node:test";
import { hotp } from "../src/hotp.js";

const SECRET = new Uint8Array(Buffer.from("12345678901234567890", "ascii"));

test("number and bigint counters agree", () => {
  assert.equal(hotp(SECRET, 9n), hotp(SECRET, 9));
});

test("the largest safe number counter agrees with its exact bigint", () => {
  assert.equal(hotp(SECRET, Number.MAX_SAFE_INTEGER), hotp(SECRET, 9007199254740991n));
});

test("unsafe number counters are rejected instead of generating a code for rounded input", () => {
  // Both adjacent bigint counters collapse to the same JavaScript number.
  const first = 9007199254740992n;
  const next = first + 1n;
  assert.equal(Number(first), Number(next));
  for (const counter of [Number(first), Number(next), 1e20]) {
    assert.throws(() => hotp(SECRET, counter), /safe integer; use bigint/);
  }
  assert.notEqual(hotp(SECRET, first), hotp(SECRET, next));
});

test("fractional and non-finite number counters throw RangeError", () => {
  for (const counter of [0.5, NaN, Infinity, -Infinity]) {
    assert.throws(() => hotp(SECRET, counter), RangeError);
  }
});

test("supports 6, 7 and 8 digits and keeps leading zeros", () => {
  for (const digits of [6, 7, 8]) {
    for (let c = 0; c < 200; c++) {
      assert.match(hotp(SECRET, c, { digits }), new RegExp(`^[0-9]{${digits}}$`));
    }
  }
});

test("different algorithms produce different codes for the same input", () => {
  const codes = new Set(
    ["SHA1", "SHA256", "SHA512"].map((algorithm) => hotp(SECRET, 1, { algorithm: algorithm as "SHA1" })),
  );
  assert.equal(codes.size, 3);
});

test("counters up to 2^64 − 1 are accepted; beyond that is rejected", () => {
  assert.doesNotThrow(() => hotp(SECRET, 0xffffffffffffffffn));
  assert.throws(() => hotp(SECRET, 1n << 64n), RangeError);
});

test("rejects invalid input with RangeError", () => {
  assert.throws(() => hotp(SECRET, -1), RangeError);
  assert.throws(() => hotp(SECRET, 0, { digits: 5 }), RangeError);
  assert.throws(() => hotp(SECRET, 0, { digits: 9 }), RangeError);
  assert.throws(() => hotp(SECRET, 0, { digits: 6.5 }), RangeError);
  assert.throws(() => hotp(new Uint8Array(0), 0), RangeError);
});
