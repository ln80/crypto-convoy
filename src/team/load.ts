// Loading a team's verified chain (§6.1 steps 1–2), shared by sessions and the vault's leave check.
import type { Anchor } from "../encoding/link.js";
import { trustFailure } from "../errors.js";
import { callPort, type AnchorStore, type RecordStore } from "../ports.js";
import { parseListedMemberKeys } from "../records/member-keys.js";
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
  extraRoots: readonly Anchor[] = [],
): Promise<{ chain: VerifiedChain; server: ServerState | null }> {
  const server = await readServerState(ports, accountId, teamId, bundles);
  const local = ports.anchors ? await callPort(() => ports.anchors!.getAnchor(accountId, teamId)) : null;
  // The roots: the floor, which only the vault writes from a verified chain, and this device's anchor.
  // The team-state, which others can write, counts only on their chain; it is a root only for keys with no floor (D-52).
  const floor = bundles[0]?.floor;
  // A root only for keys with no floor: there an unreadable one stops here; with a floor it is absent (D-52, D-62).
  if (!floor && server && !server.anchor) throw trustFailure("state_unreadable");
  // In the vault's context, its own anchor is a root too (D-54).
  const roots = [floor, local, ...extraRoots, floor ? undefined : server?.anchor].filter((a): a is Anchor => a !== null && a !== undefined);
  const state = floor ? (server?.anchor ?? undefined) : undefined;
  return { chain: await verifiedChain(ports, teamId, roots, state), server };
}

/**
 * The chain from the lowest of `anchors` (version 1 with none), verified to contain them all, and
 * `state` if it lies on it (§6.1 step 2). Throws `TRUST_FAILURE`.
 */
export async function verifiedChain(ports: ChainPorts, teamId: string, anchors: readonly Anchor[], state?: Anchor): Promise<VerifiedChain> {
  // From the lowest anchor: what lies below it is pinned by hash and fetched only when needed (§6.1 step 2).
  const fromVersion = anchors.length > 0 ? Math.min(...anchors.map((a) => a.version)) : 1;
  const records = await fetchVersions(ports, teamId, fromVersion);
  // A record that fails its checks is left out: one bad record never stops the team (D-58).
  const memberKeys = parseListedMemberKeys(await callPort(() => ports.store.list({ type: "member-keys", teamId })), { teamId });
  return verifyChain({ records, anchors, memberKeys, ...(state ? { state } : {}) });
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
