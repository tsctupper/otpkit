// RFC 4648 §6 Base32 — the encoding authenticator apps use for shared secrets
// (e.g. the string you scan or type into Google Authenticator). Decoding is
// tolerant of lowercase, whitespace, and missing `=` padding, because real-world
// secrets are copied by hand; encoding emits canonical padded output.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Flat lookup table: 255 marks "not in the alphabet". A typed array (rather than
// an object map) avoids prototype-key surprises and keeps lookups branch-light.
const DECODE_TABLE = new Uint8Array(128).fill(255);
for (let i = 0; i < ALPHABET.length; i++) {
  DECODE_TABLE[ALPHABET.charCodeAt(i)] = i;
  DECODE_TABLE[ALPHABET.toLowerCase().charCodeAt(i)] = i;
}

/**
 * Decode an RFC 4648 Base32 string to raw bytes.
 *
 * Lowercase letters, whitespace, and trailing `=` padding are accepted. Anything
 * else — including `=` anywhere but the end — throws, so a typo in a stored
 * secret fails loudly instead of silently producing the wrong key.
 *
 * @throws {Error} on a character outside the Base32 alphabet or misplaced padding.
 */
export function base32Decode(input: string): Uint8Array {
  const stripped = input.replace(/\s/g, "");
  // Trim trailing padding with a loop, not /=+$/: that regex is quadratic on
  // long runs of "=" followed by another character (polynomial ReDoS).
  let end = stripped.length;
  while (end > 0 && stripped.charCodeAt(end - 1) === 61 /* "=" */) end--;
  const clean = stripped.slice(0, end);
  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));

  let bits = 0;
  let value = 0;
  let written = 0;

  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    const idx = code < 128 ? DECODE_TABLE[code] : 255;
    if (idx === undefined || idx === 255) {
      throw new Error(`Invalid Base32 character: ${JSON.stringify(clean[i])}`);
    }
    value = ((value << 5) | idx) & 0xffff; // only the low 12 bits are ever needed
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[written++] = (value >>> bits) & 0xff;
    }
  }
  return out;
}

/** Encode raw bytes to a canonical, `=`-padded RFC 4648 Base32 string. */
export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;

  for (const byte of bytes) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET.charAt((value >>> bits) & 0x1f);
    }
  }
  if (bits > 0) out += ALPHABET.charAt((value << (5 - bits)) & 0x1f);

  return out.padEnd(Math.ceil(out.length / 8) * 8, "=");
}
