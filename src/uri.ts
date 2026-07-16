import { randomBytes } from "node:crypto";
import { base32Encode } from "./base32.js";
import type { OtpAlgorithm } from "./hotp.js";

/**
 * Cryptographically-random secret. Default 20 bytes (160 bits) — the minimum
 * RFC 4226 §4 R6 recommends.
 */
export function generateSecret(bytes = 20): Uint8Array {
  if (!Number.isInteger(bytes) || bytes < 16) throw new RangeError("secret must be at least 16 bytes");
  return new Uint8Array(randomBytes(bytes));
}

export interface OtpauthParams {
  /** Account label shown in the authenticator, e.g. the user's email. */
  label: string;
  /** Issuer / app name. */
  issuer?: string;
  digits?: number;
  period?: number;
  algorithm?: OtpAlgorithm;
}

/**
 * Build the `otpauth://totp/...` provisioning URI authenticator apps import
 * (usually as a QR code), per the de-facto Key URI Format. The secret is
 * Base32-encoded and unpadded, as those apps expect.
 */
export function otpauthURL(secret: Uint8Array, params: OtpauthParams): string {
  const { label, issuer, digits = 6, period = 30, algorithm = "SHA1" } = params;
  const accountName = issuer ? `${issuer}:${label}` : label;
  const query = new URLSearchParams({
    secret: base32Encode(secret).replace(/=+$/, ""),
    algorithm,
    digits: String(digits),
    period: String(period),
  });
  if (issuer) query.set("issuer", issuer);
  return `otpauth://totp/${encodeURIComponent(accountName)}?${query.toString()}`;
}
