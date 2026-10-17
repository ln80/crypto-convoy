import { unsupported } from "../errors.js";
import { cc1 } from "./cc1/index.js";
import { loadSodium } from "./cc1/sodium.js";
import type { Suite } from "./suite.js";

const SUITES: ReadonlyMap<string, Suite> = new Map([cc1].map((suite) => [suite.id, suite]));

/** Writers always use the current suite (§10). */
export const CURRENT_SUITE: Suite = cc1;

/** Readers use the suite a record declares; unknown ids fail before any crypto (SP-17). */
export function suiteFor(id: unknown): Suite {
  const suite = typeof id === "string" ? SUITES.get(id) : undefined;
  if (!suite) throw unsupported();
  return suite;
}

/** Loads every suite's primitives. Awaited once by the public entry points. */
export function ready(): Promise<void> {
  return loadSodium();
}
