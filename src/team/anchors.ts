// Anchors against rollback (§4.4, §6.1 steps 1 and 7, SP-07).
import type { Anchor } from "../encoding/link.js";
import { StoreConflictError, isConvoyError, trustFailure } from "../errors.js";
import { callPort, type TeamStateKey } from "../ports.js";
import { createTeamState, openTeamState, parseTeamState, readTeamStateRevision, teamStateToJson } from "../records/team-state.js";
import { keysHash } from "../records/member-keys.js";
import type { VerifiedChain } from "./chain.js";
import type { MemberBundle, TeamPorts } from "./context.js";

export interface ServerState {
  readonly revision: number;
  /** Null when it doesn't open: absent, which happens only where the newest keys hold a floor (D-62, D-63). */
  readonly anchor: Anchor | null;
  /** At a `v` or suite this library doesn't read: absent, and never replaced, since readers ship first (§10, D-62). */
  readonly unknownVersion?: boolean;
}

const stateKey = (accountId: string, teamId: string): TeamStateKey => ({ type: "team-state", accountId, teamId });

/**
 * The server's `team-state` (§4.4). With a floor, it counts only under the newest bundle's key, and one that
 * doesn't open there is absent (D-62, D-63). With no floor it is a root: opened with any bundle held, and
 * any failure is thrown.
 */
export async function readServerState(
  ports: Pick<TeamPorts, "store" | "suite">,
  accountId: string,
  teamId: string,
  bundles: readonly MemberBundle[],
): Promise<ServerState | null> {
  const json = await callPort(() => ports.store.get(stateKey(accountId, teamId)));
  if (json === null || json === undefined) return null;
  // Read before the version, so the anchor advance can replace what doesn't open (D-62).
  const revision = readTeamStateRevision(json);
  const floored = bundles[0]?.floor !== undefined;
  let record;
  try {
    record = parseTeamState(json, { accountId, teamId });
  } catch (error) {
    if (!floored) throw error;
    return { revision, anchor: null, unknownVersion: isConvoyError(error, "UNSUPPORTED_VERSION") };
  }
  // Keys being replaced don't count: a state written under them stops nothing once the account re-keys (D-63).
  for (const bundle of floored ? bundles.slice(0, 1) : bundles) {
    try {
      return { revision, anchor: openTeamState(record, bundle.pairs.teamStateKey) };
    } catch {
      // With no floor, another bundle may have written it (after a re-key).
    }
  }
  if (!floored) throw trustFailure("state_unreadable");
  return { revision, anchor: null };
}

/** Advances the anchor to the newest verified version, locally and on the server (§6.1 step 7), written under the newest bundle's key. */
export async function advanceAnchor(
  ports: TeamPorts,
  accountId: string,
  teamId: string,
  chain: VerifiedChain,
  bundles: readonly MemberBundle[],
  server: ServerState | null,
): Promise<void> {
  const bundle = bundles[0]!;
  const newest = chain.records[chain.records.length - 1]!;
  const anchor = { version: newest.version, hash: chain.hashes.get(newest.version)! };
  const local = await callPort(() => ports.anchors.getAnchor(accountId, teamId));
  if (!local || local.version < anchor.version) await callPort(() => ports.anchors.setAnchor(accountId, teamId, anchor));

  // An unreadable one is replaced only by keys the tip's roster holds: a context holding older keys never
  // overwrites the current ones', so two contexts never take turns (D-62).
  const held = newest.roster.some(
    (e) => e.accountId === accountId && e.memberKeysVersion === bundle.memberKeysVersion && ports.suite.equal(e.keysHash, keysHash(ports.suite, bundle.published)),
  );
  for (let attempt = 0; attempt < 3; attempt++) {
    if (server?.anchor && server.anchor.version >= anchor.version) return;
    if (server && !server.anchor && (!held || server.unknownVersion)) return;
    const revision = (server?.revision ?? 0) + 1;
    const record = createTeamState(ports.suite, { accountId, teamId }, revision, bundle.pairs.teamStateKey, anchor);
    try {
      await callPort(() =>
        ports.store.commit([
          { op: "compare-and-set", key: stateKey(accountId, teamId), expectedRevision: server?.revision ?? null, record: teamStateToJson(record) },
        ]),
      );
      return;
    } catch (error) {
      if (!(error instanceof StoreConflictError)) throw error;
      // Another device of this account wrote first: its anchor must be in our chain too; a newer one is left to the next open.
      server = await readServerState(ports, accountId, teamId, bundles);
      if (server?.anchor && server.anchor.version <= anchor.version) {
        const hash = chain.hashes.get(server.anchor.version);
        if (!hash || !ports.suite.equal(hash, server.anchor.hash)) throw trustFailure("chain_conflict");
      }
    }
  }
}
