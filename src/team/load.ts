// Loading a team's verified chain (§6.1 steps 1–2), shared by sessions and the vault's leave check.
import type { Anchor } from "../encoding/link.js";
import { callPort, type AnchorStore, type RecordStore } from "../ports.js";
import { parseMemberKeys } from "../records/member-keys.js";
import { parseTeamKeyVersion } from "../records/team-key-version.js";
import type { Suite } from "../suites/suite.js";
import { readServerState, type ServerState } from "./anchors.js";
import { verifyChain, type VerifiedChain } from "./chain.js";
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
  invite?: Anchor,
): Promise<{ chain: VerifiedChain; server: ServerState | null }> {
  const { store } = ports;
  const server = await readServerState(ports, accountId, teamId, bundles);
  const local = ports.anchors ? await callPort(() => ports.anchors!.getAnchor(accountId, teamId)) : null;
  const anchors = [local, server?.anchor, invite].filter((a): a is Anchor => a !== null && a !== undefined);
  const records = (await callPort(() => store.list({ type: "team-key-version", teamId, fromVersion: 1 }))).map((json) =>
    parseTeamKeyVersion(json, { teamId }),
  );
  const memberKeys = (await callPort(() => store.list({ type: "member-keys", teamId }))).map((json) =>
    parseMemberKeys(json, { teamId, accountId: (json as { accountId: string }).accountId }),
  );
  return { chain: verifyChain({ records, anchors, memberKeys }), server };
}
