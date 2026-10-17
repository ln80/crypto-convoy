import type { Clock, RecordStore, ResolvedSettings } from "../ports.js";
import type { Suite } from "../suites/suite.js";

/** What content operations need. Link clients have no account and no local keys. */
export interface ContentPorts {
  readonly suite: Suite;
  readonly store: RecordStore;
  readonly clock: Clock;
  readonly settings: ResolvedSettings;
}

/** A part as the application gives and gets it: content plus its opaque `meta` (D-16). */
export interface PartInput {
  readonly content: Uint8Array;
  readonly meta?: Uint8Array;
}

export interface OpenedPart {
  readonly content: Uint8Array;
  readonly meta: Uint8Array;
}
