import { ConvoyError, StoreConflictError } from "../errors.js";
import { callPort, type AnchorStore, type Clock, type RecordStore, type ResolvedSettings, type WriteOp } from "../ports.js";
import type { Anchor } from "../encoding/link.js";
import type { MemberKeys } from "../records/member-keys.js";
import type { MemberKeyPairs } from "../records/member-keys-wrap.js";
import type { Suite } from "../suites/suite.js";

/** What a team session works with. No OPRF and no account key (D-03). */
export interface TeamPorts {
  readonly suite: Suite;
  readonly store: RecordStore;
  readonly anchors: AnchorStore;
  readonly clock: Clock;
  readonly settings: ResolvedSettings;
}

/** One set of this account's member keys for the team, opened by the vault. */
export interface MemberBundle {
  readonly memberKeysVersion: number;
  readonly published: MemberKeys;
  readonly pairs: MemberKeyPairs;
  /** The anchor floor the bundle carries: used when a device has no other anchor (§6.1 step 1, D-48). */
  readonly floor?: Anchor;
}

/** Commits; a refused write is `STALE_VERSION` (§6.6 step 5, §12). */
export async function commitTeam(store: RecordStore, ops: readonly WriteOp[]): Promise<void> {
  try {
    await callPort(() => store.commit(ops));
  } catch (error) {
    if (error instanceof StoreConflictError) throw new ConvoyError("STALE_VERSION");
    throw error;
  }
}
