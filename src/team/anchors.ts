// Anchors against rollback (§4.4, §6.1 steps 1 and 7, SP-07).
import type { Anchor } from "../encoding/link.js";
import { StoreConflictError, trustFailure } from "../errors.js";
import { callPort, type TeamStateKey } from "../ports.js";
import { createTeamState, openTeamState, parseTeamState, teamStateToJson } from "../records/team-state.js";
import type { VerifiedChain } from "./chain.js";
import type { MemberBundle, TeamPorts } from "./context.js";

export interface ServerState {
  readonly revision: number;
  readonly anchor: Anchor;
}

const stateKey = (accountId: string, teamId: string): TeamStateKey => ({ type: "team-state", accountId, teamId });

/** The server's `team-state`, opened with any of this account's team state keys; unreadable is `state_unreadable`. */
export async function readServerState(
  ports: TeamPorts,
  accountId: string,
  teamId: string,
  bundles: readonly MemberBundle[],
): Promise<ServerState | null> {
  const json = await callPort(() => ports.store.get(stateKey(accountId, teamId)));
  if (json === null || json === undefined) return null;
  const record = parseTeamState(json, { accountId, teamId });
  for (const bundle of bundles) {
    try {
      return { revision: record.revision, anchor: openTeamState(record, bundle.pairs.teamStateKey) };
    } catch {
      // Another bundle may have written it (after a re-key).
    }
  }
  throw trustFailure("state_unreadable");
}

/** Local anchor, server anchor and invite anchor: every one must be in the chain (§6.1 step 1). */
export async function collectAnchors(
  ports: TeamPorts,
  accountId: string,
  teamId: string,
  server: ServerState | null,
  invite?: Anchor,
): Promise<Anchor[]> {
  const local = await callPort(() => ports.localKeys.getAnchor(accountId, teamId));
  return [local, server?.anchor, invite].filter((a): a is Anchor => a !== null && a !== undefined);
}

/** Advances the anchor to the newest verified version, locally and on the server (§6.1 step 7). */
export async function advanceAnchor(
  ports: TeamPorts,
  accountId: string,
  teamId: string,
  chain: VerifiedChain,
  bundle: MemberBundle,
  server: ServerState | null,
): Promise<void> {
  const newest = chain.records[chain.records.length - 1]!;
  const anchor = { version: newest.version, hash: chain.hashes.get(newest.version)! };
  const local = await callPort(() => ports.localKeys.getAnchor(accountId, teamId));
  if (!local || local.version < anchor.version) await callPort(() => ports.localKeys.setAnchor(accountId, teamId, anchor));

  for (let attempt = 0; attempt < 3; attempt++) {
    if (server && server.anchor.version >= anchor.version) return;
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
      // Another device of this account wrote first: its anchor must be in our chain too.
      server = await readServerState(ports, accountId, teamId, [bundle]);
      if (server && server.anchor.version <= anchor.version) {
        const hash = chain.hashes.get(server.anchor.version);
        if (!hash || !ports.suite.equal(hash, server.anchor.hash)) throw trustFailure("chain_conflict");
      }
    }
  }
}
