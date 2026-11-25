// Only the Node test APIs used by this project. Included in the test compiler configuration.
declare module "node:test" {
  export function test(name: string, body: () => void | Promise<void>): Promise<void>;
}

declare module "node:assert/strict" {
  type Scalar = string | number | bigint | boolean | null | undefined;
  const assert: {
    equal<T extends Scalar>(actual: Scalar, expected: T, message?: string): asserts actual is T;
    notEqual(actual: Scalar, expected: Scalar): void;
    deepEqual(actual: Uint8Array, expected: Uint8Array): void;
    notDeepEqual(actual: Uint8Array, expected: Uint8Array): void;
    ok(value: Scalar, message?: string): asserts value;
    match(text: string, expression: RegExp): void;
    throws(run: () => void, error: RegExp | RangeErrorConstructor, message?: string): void;
    doesNotThrow(run: () => void): void;
  };
  export default assert;
}

declare const process: { hrtime: { bigint(): bigint } };

declare class URL {
  constructor(text: string);
  readonly searchParams: {
    get(name: string): string | null;
    has(name: string): boolean;
  };
}
