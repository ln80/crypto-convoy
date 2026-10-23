// Loading a team's verified chain (§6.1 steps 1–2), shared by sessions and the vault's leave check.
import type { Anchor } from "../encoding/link.js";
import { trustFailure } from "../errors.js";
import { callPort, type AnchorStore, type RecordStore } from "../ports.js";
import { parseMemberKeys } from "../records/member-keys.js";
import { parseTeamKeyVersion } from "../records/team-key-version.js";
import type { Suite } from "../suites/suite.js";
import { readServerState, type ServerState } from "./anchors.js";
import { extendChain, verifyChain, type VerifiedChain } from "./chain.js";
import type { MemberBundle } from "./context.js";

export interface ChainPorts {
  readonly suite: Suite;
  readonly store: RecordStore;
  readonly anchors?: AnchorStore;
}

export async function loadChain(
  ports: ChainPorts,
  accountId: string,
  teamId: string,
  bundles: readonly MemberBundle[],
): Promise<{ chain: VerifiedChain; server: ServerState | null }> {
  const server = await readServerState(ports, accountId, teamId, bundles);
  const local = ports.anchors ? await callPort(() => ports.anchors!.getAnchor(accountId, teamId)) : null;
  const anchors = [local, server?.anchor].filter((a): a is Anchor => a !== null && a !== undefined);
  // The newest bundle's floor, unless below every other anchor: it never adds a download, and no older team-state wins (D-50).
  const floor = bundles[0]?.floor;
  if (floor && (anchors.length === 0 || anchors.some((a) => a.version <= floor.version))) anchors.push(floor);
  return { chain: await verifiedChain(ports, teamId, anchors), server };
}

/** The chain from the lowest of `anchors` (version 1 with none), verified to contain them all (§6.1 step 2). Throws `TRUST_FAILURE`. */
export async function verifiedChain(ports: ChainPorts, teamId: string, anchors: readonly Anchor[]): Promise<VerifiedChain> {
  // From the lowest anchor: what lies below it is pinned by hash and fetched only when needed (§6.1 step 2).
  const fromVersion = anchors.length > 0 ? Math.min(...anchors.map((a) => a.version)) : 1;
  const records = await fetchVersions(ports, teamId, fromVersion);
  const memberKeys = (await callPort(() => ports.store.list({ type: "member-keys", teamId }))).map((json) =>
    parseMemberKeys(json, { teamId, accountId: (json as { accountId: string }).accountId }),
  );
  return verifyChain({ records, anchors, memberKeys });
}

async function fetchVersions(ports: ChainPorts, teamId: string, fromVersion: number) {
  const jsons = await callPort(() => ports.store.list({ type: "team-key-version", teamId, fromVersion }));
  return jsons.map((json) => parseTeamKeyVersion(json, { teamId }));
}

/** The chain reaching down to `version`, fetching older records when needed (§6.2). Throws `TRUST_FAILURE`. */
export async function chainFrom(ports: ChainPorts, teamId: string, chain: VerifiedChain, version: number): Promise<VerifiedChain> {
  const first = chain.records[0]!.version;
  if (version >= first) return chain;
  const older = (await fetchVersions(ports, teamId, Math.max(version, 1))).filter((r) => r.version < first);
  if (older[0]?.version !== Math.max(version, 1)) throw trustFailure("rollback");
  return extendChain(chain, older);
}
