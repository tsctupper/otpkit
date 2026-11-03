import assert from "node:assert/strict";
import { test } from "node:test";
import { base32Decode } from "../src/base32.js";
import { generateSecret, otpauthURL } from "../src/uri.js";

test("otpauthURL round-trips the secret through Base32", () => {
  const secret = generateSecret(20);
  const url = otpauthURL(secret, { label: "alice@example.com", issuer: "OtpKit" });
  assert.match(url, /^otpauth:\/\/totp\/OtpKit:alice%40example\.com\?/);
  const parsed = new URL(url);
  assert.equal(parsed.searchParams.get("issuer"), "OtpKit");
  assert.equal(parsed.searchParams.get("algorithm"), "SHA1");
  assert.equal(parsed.searchParams.get("digits"), "6");
  assert.equal(parsed.searchParams.get("period"), "30");
  const secretParam = parsed.searchParams.get("secret");
  assert.ok(secretParam);
  assert.ok(!secretParam.includes("="), "secret is unpadded");
  assert.deepEqual(base32Decode(secretParam), secret);
});

test("issuer and label are percent-encoded separately; spaces are %20, never +", () => {
  const secret = generateSecret();
  const url = otpauthURL(secret, { label: "john doe", issuer: "ACME Co" });
  assert.match(url, /^otpauth:\/\/totp\/ACME%20Co:john%20doe\?/);
  assert.ok(url.includes("issuer=ACME%20Co"));
  assert.ok(!url.includes("+"));
});

test("a label that itself contains ':' or '&' cannot inject parameters", () => {
  const url = otpauthURL(generateSecret(), { label: "a:b&digits=8", issuer: "x&period=1" });
  const parsed = new URL(url);
  assert.equal(parsed.searchParams.get("digits"), "6");
  assert.equal(parsed.searchParams.get("period"), "30");
  assert.equal(parsed.searchParams.get("issuer"), "x&period=1");
});

test("issuer is optional", () => {
  const url = otpauthURL(generateSecret(), { label: "alice@example.com" });
  assert.match(url, /^otpauth:\/\/totp\/alice%40example\.com\?/);
  assert.equal(new URL(url).searchParams.has("issuer"), false);
});

test("otpauthURL validates its inputs", () => {
  const s = generateSecret();
  assert.throws(() => otpauthURL(s, { label: "" }), RangeError);
  assert.throws(() => otpauthURL(s, { label: "x", digits: 9 }), RangeError);
  assert.throws(() => otpauthURL(s, { label: "x", period: 0 }), RangeError);
  assert.throws(() => otpauthURL(s, { label: "x", period: 1.5 }), RangeError);
});

test("generateSecret enforces the 16-byte floor and produces distinct secrets", () => {
  assert.throws(() => generateSecret(8), RangeError);
  assert.throws(() => generateSecret(19.5), RangeError);
  assert.equal(generateSecret(32).length, 32);
  assert.equal(generateSecret().length, 20);
  assert.notDeepEqual(generateSecret(), generateSecret());
});

test("secret parameter is unpadded whether or not the encoding needs padding", () => {
  for (const bytes of [16, 20]) {
    // 16 bytes → 26 chars + 6 padding; 20 bytes → exactly 32 chars, no padding.
    const secret = generateSecret(bytes);
    const param = new URL(otpauthURL(secret, { label: "x" })).searchParams.get("secret");
    assert.ok(param && !param.includes("="));
    assert.deepEqual(base32Decode(param), secret);
  }
});
