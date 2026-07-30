import assert from "node:assert/strict";
import { test } from "node:test";
import { base32Decode, base32Encode } from "../src/base32.js";
import { hotp } from "../src/hotp.js";
import { generateSecret, otpauthURL } from "../src/uri.js";
import { totp, verifyTotp } from "../src/totp.js";

const ascii = (s: string) => new Uint8Array(Buffer.from(s, "ascii"));

// RFC 4648 §10 — canonical Base32 test vectors
const BASE32_VECTORS: ReadonlyArray<readonly [string, string]> = [
  ["", ""],
  ["f", "MY======"],
  ["fo", "MZXQ===="],
  ["foo", "MZXW6==="],
  ["foob", "MZXW6YQ="],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI======"],
];

test("Base32 encodes the RFC 4648 §10 vectors", () => {
  for (const [plain, encoded] of BASE32_VECTORS) {
    assert.equal(base32Encode(ascii(plain)), encoded);
  }
});

test("Base32 decodes the RFC 4648 §10 vectors, padding optional", () => {
  for (const [plain, encoded] of BASE32_VECTORS) {
    assert.equal(Buffer.from(base32Decode(encoded)).toString("ascii"), plain);
    assert.equal(Buffer.from(base32Decode(encoded.replace(/=/g, ""))).toString("ascii"), plain);
  }
});

// RFC 4226 Appendix D — HOTP for secret "12345678901234567890"
const HOTP_SECRET = ascii("12345678901234567890");
const HOTP_EXPECTED = [
  "755224", "287082", "359152", "969429", "338314",
  "254676", "287922", "162583", "399871", "520489",
];

test("HOTP matches every RFC 4226 Appendix D vector", () => {
  for (let counter = 0; counter < HOTP_EXPECTED.length; counter++) {
    assert.equal(hotp(HOTP_SECRET, counter), HOTP_EXPECTED[counter]);
  }
});

// RFC 6238 Appendix B — TOTP across SHA-1/256/512, 8 digits
const SEED = {
  SHA1: ascii("12345678901234567890"),
  SHA256: ascii("12345678901234567890123456789012"),
  SHA512: ascii("1234567890123456789012345678901234567890123456789012345678901234"),
} as const;

// [unix seconds, SHA1, SHA256, SHA512]
const TOTP_VECTORS: ReadonlyArray<readonly [number, string, string, string]> = [
  [59, "94287082", "46119246", "90693936"],
  [1111111109, "07081804", "68084774", "25091201"],
  [1111111111, "14050471", "67062674", "99943326"],
  [1234567890, "89005924", "91819424", "93441116"],
  [2000000000, "69279037", "90698825", "38618901"],
  [20000000000, "65353130", "77737706", "47863826"],
];

test("TOTP matches every RFC 6238 Appendix B vector (SHA-1/256/512)", () => {
  for (const [seconds, sha1, sha256, sha512] of TOTP_VECTORS) {
    const base = { digits: 8, period: 30, now: seconds * 1000 } as const;
    assert.equal(totp(SEED.SHA1, { ...base, algorithm: "SHA1" }), sha1);
    assert.equal(totp(SEED.SHA256, { ...base, algorithm: "SHA256" }), sha256);
    assert.equal(totp(SEED.SHA512, { ...base, algorithm: "SHA512" }), sha512);
  }
});

test("verifyTotp accepts the live step and rejects one outside the window", () => {
  const at = 59_000;
  assert.equal(verifyTotp("94287082", SEED.SHA1, { digits: 8, now: at }), true);
  assert.equal(verifyTotp("94287082", SEED.SHA1, { digits: 8, now: at + 60_000 }), false);
  assert.equal(verifyTotp("94287082", SEED.SHA1, { digits: 8, now: at + 60_000, window: 2 }), true);
});

test("generateSecret + otpauthURL round-trip through Base32", () => {
  const secret = generateSecret(20);
  assert.equal(secret.length, 20);
  const url = otpauthURL(secret, { label: "alice@example.com", issuer: "OtpKit", digits: 6, period: 30 });
  assert.match(url, /^otpauth:\/\/totp\/OtpKit:alice%40example\.com\?/);
  const parsed = new URL(url);
  assert.equal(parsed.searchParams.get("issuer"), "OtpKit");
  const secretParam = parsed.searchParams.get("secret");
  assert.ok(secretParam);
  assert.ok(!secretParam.includes("="), "secret is unpadded");
  assert.deepEqual(base32Decode(secretParam), secret);
});

test("otpauthURL percent-encodes issuer and label separately", () => {
  const secret = generateSecret();
  const url = otpauthURL(secret, { label: "john doe", issuer: "ACME Co" });
  assert.match(url, /^otpauth:\/\/totp\/ACME%20Co:john%20doe\?/);
  const noIssuer = otpauthURL(secret, { label: "alice@example.com" });
  assert.match(noIssuer, /^otpauth:\/\/totp\/alice%40example\.com\?/);
  assert.equal(new URL(noIssuer).searchParams.has("issuer"), false);
});

test("HOTP accepts bigint counters and rejects invalid input", () => {
  assert.equal(hotp(HOTP_SECRET, 9n), hotp(HOTP_SECRET, 9));
  assert.throws(() => hotp(HOTP_SECRET, -1), RangeError);
  assert.throws(() => hotp(HOTP_SECRET, 0, { digits: 5 }), RangeError);
  assert.throws(() => hotp(HOTP_SECRET, 0, { digits: 9 }), RangeError);
  assert.throws(() => hotp(new Uint8Array(0), 0), RangeError);
});

test("TOTP validates period and clock inputs", () => {
  assert.throws(() => totp(SEED.SHA1, { period: 0 }), RangeError);
  assert.throws(() => totp(SEED.SHA1, { period: -30 }), RangeError);
  assert.throws(() => totp(SEED.SHA1, { now: Number.NaN }), RangeError);
  assert.throws(() => totp(SEED.SHA1, { now: 5_000, epoch: 100 }), RangeError);
});

test("verifyTotp never throws when the drift window reaches past the epoch", () => {
  // At t=0 a ±1 window would touch counter −1; those steps are skipped.
  assert.equal(verifyTotp(hotp(SEED.SHA1, 0), SEED.SHA1, { now: 0 }), true);
  assert.equal(verifyTotp("000000", SEED.SHA1, { now: 0 }), false);
});

test("verifyTotp rejects malformed tokens without touching the secret", () => {
  assert.equal(verifyTotp("94287082", SEED.SHA1, { digits: 6, now: 59_000 }), false); // wrong length
  assert.equal(verifyTotp("9428708a", SEED.SHA1, { digits: 8, now: 59_000 }), false); // non-digit
  assert.equal(verifyTotp("", SEED.SHA1, { now: 59_000 }), false);
  assert.throws(() => verifyTotp("94287082", SEED.SHA1, { digits: 8, window: -1 }), RangeError);
  assert.throws(() => verifyTotp("94287082", SEED.SHA1, { digits: 8, window: 1.5 }), RangeError);
});

test("Base32 decode is tolerant of case and whitespace but rejects bad characters", () => {
  assert.deepEqual(base32Decode("mzxw 6ytb"), base32Decode("MZXW6YTB"));
  assert.throws(() => base32Decode("MZXW6YT1"), /Invalid Base32 character/);
  assert.throws(() => base32Decode("MZXW6YT!"), /Invalid Base32 character/);
});

test("generateSecret enforces the 16-byte floor and produces distinct secrets", () => {
  assert.throws(() => generateSecret(8), RangeError);
  assert.throws(() => generateSecret(19.5), RangeError);
  const a = generateSecret(32);
  assert.equal(a.length, 32);
  assert.notDeepEqual(generateSecret(), generateSecret());
});
