import { ConvoyError, StoreConflictError } from "../errors.js";
import { callPort, type RecordStore, type WriteOp } from "../ports.js";

export { callPort };

/** Commits; a refused write (an id already used, a version no longer current, §11) is `STALE_VERSION`. */
export async function commitContent(store: RecordStore, ops: readonly WriteOp[]): Promise<void> {
  try {
    await callPort(() => store.commit(ops));
  } catch (error) {
    if (error instanceof StoreConflictError) throw new ConvoyError("STALE_VERSION");
    throw error;
  }
}
