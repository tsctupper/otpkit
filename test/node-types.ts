// Compile-only checks for the private Node declarations. The runtime suite exercises the calls.
import type { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

type MustBeFalse<T extends false> = T;
type MustBeTrue<T extends true> = T;
type Digest = ReturnType<ReturnType<typeof createHmac>["digest"]>;
type QueryValue = ReturnType<URL["searchParams"]["get"]>;

export type NodeContractChecks = [
  MustBeFalse<[number, Uint8Array] extends Parameters<typeof createHmac> ? true : false>,
  MustBeFalse<[string] extends Parameters<typeof randomBytes> ? true : false>,
  MustBeFalse<[string, string] extends Parameters<typeof timingSafeEqual> ? true : false>,
  MustBeFalse<["0"] extends Parameters<Digest["readUInt32BE"]> ? true : false>,
  MustBeTrue<ReturnType<typeof process.hrtime.bigint> extends bigint ? true : false>,
  MustBeTrue<null extends QueryValue ? true : false>,
  MustBeFalse<QueryValue extends string ? true : false>,
];
