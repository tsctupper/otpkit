// RFC 4648 §6 Base32 — the encoding authenticator apps use for shared secrets
// (e.g. the string you scan or type into Google Authenticator). Decoding is
// tolerant of lowercase, spaces, and missing `=` padding, because real-world
// secrets are copied by hand; encoding emits canonical padded output.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const DECODE_MAP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) DECODE_MAP[ALPHABET[i]] = i;

/** Decode an RFC 4648 Base32 string to raw bytes. Padding/whitespace optional. */
export function base32Decode(input: string): Uint8Array {
  const clean = input.replace(/[\s=]/g, "").toUpperCase();
  if (clean.length === 0) return new Uint8Array(0);

  const out: number[] = [];
  let bits = 0;
  let value = 0;

  for (const ch of clean) {
    const idx = DECODE_MAP[ch];
    if (idx === undefined) throw new Error(`Invalid Base32 character: ${JSON.stringify(ch)}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** Encode raw bytes to a canonical, `=`-padded RFC 4648 Base32 string. */
export function base32Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let out = "";
  let bits = 0;
  let value = 0;

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 0x1f];

  while (out.length % 8 !== 0) out += "=";
  return out;
}
