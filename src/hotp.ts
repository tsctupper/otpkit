import { createHmac } from "node:crypto";

export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface HotpOptions {
  /** Digits in the generated code, 6–8 per RFC 4226 §5.3 (default 6). */
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
  // Dynamic truncation yields at most 31 bits, so codes longer than 8 digits
  // could never span their full range — RFC 4226 §5.3 defines 6–8.
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new RangeError("digits must be an integer between 6 and 8");
  }
  if (secret.length === 0) throw new RangeError("secret must not be empty");

  // 8-byte big-endian counter — RFC 4226 §5.1.
  let c = BigInt(counter);
  if (c < 0n || c > 0xffffffffffffffffn) {
    throw new RangeError("counter must be between 0 and 2^64 - 1");
  }
  const counterBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }

  const mac = createHmac(algorithm.toLowerCase(), Buffer.from(secret)).update(counterBytes).digest();

  // Dynamic truncation — RFC 4226 §5.3.
  const offset = mac.readUInt8(mac.length - 1) & 0x0f;
  const binCode = mac.readUInt32BE(offset) & 0x7fffffff;

  return (binCode % 10 ** digits).toString().padStart(digits, "0");
}
