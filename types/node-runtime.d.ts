// Compile-time contract for the Node calls in src/. Consumers use the emitted public types.
interface OtpBuffer extends Uint8Array<ArrayBuffer> {
  readUInt8(offset: number): number;
  readUInt32BE(offset: number): number;
  toString(encoding?: "ascii"): string;
}

declare const Buffer: {
  from(text: string, encoding: "ascii"): OtpBuffer;
  from(bytes: Uint8Array): OtpBuffer;
};

declare module "node:crypto" {
  interface HmacState {
    update(bytes: Uint8Array): HmacState;
    digest(): OtpBuffer;
  }

  export function createHmac(algorithm: string, key: Uint8Array): HmacState;
  export function timingSafeEqual(left: Uint8Array, right: Uint8Array): boolean;
  export function randomBytes(size: number): OtpBuffer;
}
