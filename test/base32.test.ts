import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { base32Decode, base32Encode } from "../src/base32.js";

test("decode tolerates case, whitespace and missing padding", () => {
  assert.deepEqual(base32Decode("mzxw 6ytb\n"), base32Decode("MZXW6YTB"));
  assert.deepEqual(base32Decode("MZXW6YQ"), base32Decode("MZXW6YQ="));
});

test("decode rejects characters outside the alphabet", () => {
  for (const bad of ["MZXW6YT1", "MZXW6YT!", "MZXW6YT8", "MZXW6YTé", "MZXW-6YTB"]) {
    assert.throws(() => base32Decode(bad), /Invalid Base32 character/, bad);
  }
});

test("decode rejects padding that is not at the end", () => {
  assert.throws(() => base32Decode("MZ=XW6YT"), /Invalid Base32 character/);
});

test("empty input round-trips", () => {
  assert.equal(base32Encode(new Uint8Array(0)), "");
  assert.deepEqual(base32Decode(""), new Uint8Array(0));
  assert.deepEqual(base32Decode("===="), new Uint8Array(0));
});

test("encode → decode round-trips random inputs of every length 0–64", () => {
  for (let len = 0; len <= 64; len++) {
    for (let n = 0; n < 20; n++) {
      const bytes = new Uint8Array(randomBytes(len));
      const encoded = base32Encode(bytes);
      assert.equal(encoded.length % 8, 0, "canonical output is padded to a multiple of 8");
      assert.deepEqual(base32Decode(encoded), bytes);
      assert.deepEqual(base32Decode(encoded.replace(/=+$/, "").toLowerCase()), bytes);
    }
  }
});

test("all byte values survive a round trip", () => {
  const all = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(base32Decode(base32Encode(all)), all);
});

test("decode runs in linear time on adversarial padding (no ReDoS)", () => {
  const start = process.hrtime.bigint();
  assert.throws(() => base32Decode("=".repeat(200_000) + "!"), /Invalid Base32 character/);
  assert.throws(() => base32Decode("=".repeat(200_000) + "A"), /Invalid Base32 character/);
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.ok(ms < 1000, `took ${ms}ms`);
});
