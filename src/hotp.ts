import { createHmac } from "node:crypto";

export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface HotpOptions {
  /** Digits in the generated code (default 6). */
  digits?: number;
  /** HMAC hash — default "SHA1", the value authenticator apps assume. */
  algorithm?: OtpAlgorithm;
}

/**
 * RFC 4226 HMAC-based One-Time Password.
 *
 * @param secret Raw shared-secret bytes (Base32-decode first if you hold text).
 * @param counter Moving factor; `number` or `bigint`, encoded 8-byte big-endian.
 */
export function hotp(secret: Uint8Array, counter: number | bigint, options: HotpOptions = {}): string {
  const digits = options.digits ?? 6;
  const algorithm = options.algorithm ?? "SHA1";
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new RangeError("digits must be an integer between 1 and 10");
  }

  // 8-byte big-endian counter — RFC 4226 §5.1.
  let c = BigInt(counter);
  if (c < 0n) throw new RangeError("counter must be non-negative");
  const counterBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }

  const mac = createHmac(algorithm.toLowerCase(), Buffer.from(secret)).update(counterBytes).digest();

  // Dynamic truncation — RFC 4226 §5.3.
  const offset = mac[mac.length - 1] & 0x0f;
  const binCode =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  return (binCode % 10 ** digits).toString().padStart(digits, "0");
}
