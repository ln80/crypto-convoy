// Grants: the owner rule and opening a member's team key (§4.6, §6.1 step 5, §6.5).
import { trustFailure } from "../errors.js";
import { callPort } from "../ports.js";
import { openGrant, parseGrant, type Grant } from "../records/grant.js";
import { openPreviousKey } from "../records/team-key-version.js";
import { isOwner, type VerifiedChain } from "./chain.js";
import type { MemberBundle, TeamPorts } from "./context.js";

/** A grant for version n counts only if its signer is an owner of version n (§4.5 owner rule). */
export function checkOwnerRule(grant: Grant, chain: VerifiedChain): void {
  const record = chain.records.find((r) => r.version === grant.teamKeyVersion);
  if (!record) throw trustFailure("rollback");
  if (!isOwner(record, grant.signer)) throw trustFailure("not_an_owner");
}

export async function listGrants(ports: TeamPorts, teamId: string, query: { teamKeyVersion?: number; accountId?: string; memberKeysVersion?: number }) {
  const jsons = await callPort(() => ports.store.list({ type: "grant", teamId, ...query }));
  return jsons.map((json) => parseGrant(json, { teamId, ...query }));
}

export interface OwnGrant {
  readonly grant: Grant;
  readonly bundle: MemberBundle;
  readonly teamKey: Uint8Array;
}

/** The newest grant to any of this account's keys, checked and opened (§6.1 step 5). */
export async function openOwnGrant(
  ports: TeamPorts,
  teamId: string,
  accountId: string,
  chain: VerifiedChain,
  bundles: readonly MemberBundle[],
): Promise<OwnGrant | null> {
  let best: { grant: Grant; bundle: MemberBundle } | null = null;
  for (const bundle of bundles) {
    const grants = await listGrants(ports, teamId, { accountId, memberKeysVersion: bundle.memberKeysVersion });
    for (const grant of grants) if (!best || grant.teamKeyVersion > best.grant.teamKeyVersion) best = { grant, bundle };
  }
  if (!best) return null;
  const { grant, bundle } = best;
  checkOwnerRule(grant, chain);
  const { suite } = ports;
  const ownKeys =
    suite.equal(grant.memberSigningPublicKey, bundle.pairs.signing.publicKey) &&
    suite.equal(grant.memberEncryptionPublicKey, bundle.pairs.encryption.publicKey);
  if (!ownKeys) throw trustFailure("key_mismatch");
  const teamKey = openGrant(grant, bundle.pairs.encryption);
  // Opening the link with the granted key confirms it is the key that record was made with (§4.5).
  const record = chain.records.find((r) => r.version === grant.teamKeyVersion)!;
  if (record.version > 1) suite.wipe(openPreviousKey(record, teamKey));
  return { grant, bundle, teamKey };
}
