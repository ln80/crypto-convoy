import type { Clock, ResolvedSettings } from "../ports.js";
import type { Suite } from "../suites/suite.js";

/** What content operations need: no store, content is the integration's (D-25). */
export interface ContentPorts {
  readonly suite: Suite;
  readonly clock: Clock;
  readonly settings: ResolvedSettings;
}

/** Ciphertext as the integration has it: bytes, a stream, or a fetcher called only if needed. */
export type PartSource =
  | Uint8Array
  | AsyncIterable<Uint8Array>
  | (() => Promise<Uint8Array | AsyncIterable<Uint8Array>>);

/** What the manifest says about a part, before it is opened. */
export interface PartInfo {
  readonly index: number;
  /** Opaque to the library (D-16). */
  readonly meta: Uint8Array;
  /** Ciphertext size, for the integration's own checks and progress. */
  readonly size: number;
}

export interface PartOptions {
  readonly meta?: Uint8Array;
}
