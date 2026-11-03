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
  // Key URI Format: path is `issuer:label`, each component percent-encoded
  // separately with the `:` separator left literal, as in the spec's examples.
  if (label.length === 0) throw new RangeError("label must not be empty");
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new RangeError("digits must be an integer between 6 and 8");
  }
  if (!Number.isInteger(period) || period <= 0) {
    throw new RangeError("period must be a positive integer number of seconds");
  }
  const path = issuer
    ? `${encodeURIComponent(issuer)}:${encodeURIComponent(label)}`
    : encodeURIComponent(label);
  // Built by hand rather than URLSearchParams: that encodes spaces as `+`,
  // which several authenticator apps show literally (e.g. "Acme+Corp").
  const pairs: [string, string][] = [
    ["secret", unpaddedBase32(secret)],
    ["algorithm", algorithm],
    ["digits", String(digits)],
    ["period", String(period)],
  ];
  if (issuer) pairs.push(["issuer", issuer]);
  const query = pairs.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
  return `otpauth://totp/${path}?${query}`;
}

/** Base32 without `=` padding, as authenticator apps expect in the URI. */
function unpaddedBase32(secret: Uint8Array): string {
  const encoded = base32Encode(secret);
  const pad = encoded.indexOf("=");
  return pad === -1 ? encoded : encoded.slice(0, pad);
}
