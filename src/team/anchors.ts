// Anchors against rollback (§6.1 steps 1 and 7, SP-07).
import { callPort } from "../ports.js";
import type { VerifiedChain } from "./chain.js";
import type { TeamPorts } from "./context.js";

/** Advances this context's local anchor to the newest verified version, never down (§6.1 step 7, D-66). */
export async function advanceAnchor(ports: TeamPorts, accountId: string, teamId: string, chain: VerifiedChain): Promise<void> {
  const newest = chain.records[chain.records.length - 1]!;
  const anchor = { version: newest.version, hash: chain.hashes.get(newest.version)! };
  const local = await callPort(() => ports.anchors.getAnchor(accountId, teamId));
  if (!local || local.version < anchor.version) await callPort(() => ports.anchors.setAnchor(accountId, teamId, anchor));
}
