// An outside client: no account, the anonymous view of the server.
import type { ContentPorts } from "../../src/content/context.js";
import { resolveSettings, type RecordStore } from "../../src/ports.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { fixedClock } from "../../src/testing/index.js";

export function outsider(store: RecordStore): ContentPorts {
  return { suite: cc1, store, clock: fixedClock(), settings: resolveSettings({ argon2: { write: { opslimit: 2, memlimit: 64 * 1024 * 1024 } } }) };
}
