import assert from "node:assert/strict";
import { test } from "node:test";
import { URL } from "node:url";
import { base32Decode, totp } from "@tsctupper/otpkit";
import { createDemoAccount } from "./flow.mjs";

function fixture() {
  let time = 1_800_000_000_000;
  const account = createDemoAccount({ now: () => time });
  const enrollment = account.enroll();
  assert.equal(enrollment.ok, true);
  const secret = base32Decode(enrollment.manualKey);
  return {
    account,
    enrollment,
    advance: (ms) => (time += ms),
    code: (offset = 0) => totp(secret, { now: time + offset }),
  };
}

test("published package supports enrollment, confirmation, sign-in and replay rejection", () => {
  const { account, code, advance, enrollment } = fixture();
  assert.equal(new URL(enrollment.uri).searchParams.get("secret"), enrollment.manualKey);
  assert.deepEqual(account.signIn(code()), { ok: false, reason: "not-enrolled" });
  const first = code();
  assert.deepEqual(account.confirm(first), { ok: true });
  assert.deepEqual(account.signIn(first), { ok: false, reason: "invalid-code" });
  advance(30_000);
  const next = code();
  assert.deepEqual(account.signIn(next), { ok: true });
  assert.deepEqual(account.signIn(next), { ok: false, reason: "invalid-code" });
  assert.deepEqual(account.enroll(), { ok: false, reason: "already-enrolled" });
  assert.deepEqual(account.confirm(next), { ok: false, reason: "already-enrolled" });
});

test("invalid and expired codes do not activate an account", () => {
  const { account, code } = fixture();
  assert.deepEqual(account.confirm("not-a-code"), { ok: false, reason: "invalid-code" });
  assert.deepEqual(account.confirm(code(-60_000)), { ok: false, reason: "invalid-code" });
  assert.deepEqual(account.signIn(code()), { ok: false, reason: "not-enrolled" });
  assert.deepEqual(account.confirm(code()), { ok: true });
});

test("five failures lock confirmation and enrollment; restarting enrollment does not reset failures", () => {
  const { account, code, advance, enrollment } = fixture();
  for (let i = 0; i < 4; i++) {
    assert.deepEqual(account.confirm("bad"), { ok: false, reason: "invalid-code" });
    assert.deepEqual(account.enroll(), enrollment);
  }
  const locked = { ok: false, reason: "locked", retryAfter: 30 };
  assert.deepEqual(account.confirm("bad"), locked);
  assert.deepEqual(account.confirm(code()), locked);
  assert.deepEqual(account.enroll(), locked);
  advance(29_001);
  assert.equal(account.confirm(code()).retryAfter, 1);
  advance(999);
  assert.deepEqual(account.confirm(code()), { ok: true });
});

test("sign-in failures lock the account and successful verification resets failure count", () => {
  const { account, code, advance } = fixture();
  assert.deepEqual(account.confirm(code()), { ok: true });
  advance(30_000);
  for (let i = 0; i < 4; i++) assert.equal(account.signIn(null).reason, "invalid-code");
  assert.deepEqual(account.signIn(code()), { ok: true });
  for (let i = 0; i < 4; i++) assert.equal(account.signIn("1234567").reason, "invalid-code");
  assert.deepEqual(account.signIn("bad"), { ok: false, reason: "locked", retryAfter: 30 });
  advance(30_000);
  assert.deepEqual(account.signIn(code()), { ok: true });
});

test("a future-window code prevents a lower step from being reused", () => {
  const { account, code } = fixture();
  assert.deepEqual(account.confirm(code(30_000)), { ok: true });
  assert.deepEqual(account.signIn(code()), { ok: false, reason: "invalid-code" });
});

test("pending enrollment expires even if enrollment details are requested again", () => {
  const { account, code, advance, enrollment } = fixture();
  advance(299_999);
  assert.deepEqual(account.enroll(), enrollment);
  advance(1);
  assert.deepEqual(account.confirm(code()), { ok: false, reason: "enrollment-expired" });
  assert.deepEqual(account.confirm(code()), { ok: false, reason: "not-started" });
  const fresh = account.enroll();
  assert.notEqual(fresh.manualKey, enrollment.manualKey);
  const secret = base32Decode(fresh.manualKey);
  assert.deepEqual(account.confirm(totp(secret, { now: 1_800_000_300_000 })), { ok: true });
});

test("fresh accounts cannot confirm before enrollment", () => {
  assert.deepEqual(createDemoAccount().confirm("123456"), { ok: false, reason: "not-started" });
});
