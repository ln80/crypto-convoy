// Records an attacker could build: with stolen or own keys, outside the library's checks.
import { openBundles } from "../../src/account/member-custody.js";
import type { Vault } from "../../src/account/vault.js";
import { createGrant, grantToJson } from "../../src/records/grant.js";
import { createMemberKeys, memberKeysToJson } from "../../src/records/member-keys.js";
import { bundleKeyPairs, generateBundle } from "../../src/records/member-keys-wrap.js";
import { createTeamKeyVersion, parseTeamKeyVersion, recordHash, teamKeyVersionToJson } from "../../src/records/team-key-version.js";
import type { RecordStore } from "../../src/ports.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import type { MemberBundle } from "../../src/team/context.js";

/** Keys a member holds (AS-07): their newest bundle for the team. */
export async function bundleOf(vault: Vault, teamId = "team-1"): Promise<MemberBundle> {
  return (await openBundles(vault.ports, vault.requireAccount(), teamId))[0]!;
}

/** Fresh keys with no member keys record behind them. */
export function strangerKeys() {
  return bundleKeyPairs(cc1, generateBundle(cc1));
}

type Pairs = MemberBundle["pairs"];

export async function versionRecord(store: RecordStore, teamId: string, version: number) {
  return parseTeamKeyVersion(await store.get({ type: "team-key-version", teamId, version }), { teamId });
}

/** A version record signed with `signer` keys, chained after the served record `version − 1`. */
export async function forgeVersion(
  store: RecordStore,
  input: { teamId?: string; version: number; owners: { accountId: string; keys: Pairs }[]; signer: { accountId: string; keys: Pairs } },
) {
  const teamId = input.teamId ?? "team-1";
  const previous = await versionRecord(store, teamId, input.version - 1);
  const record = createTeamKeyVersion(cc1, {
    teamId,
    version: input.version,
    prevHash: recordHash(previous),
    owners: input.owners.map((o) => ({ accountId: o.accountId, signingPublicKey: o.keys.signing.publicKey })),
    createdAt: 1,
    signer: { accountId: input.signer.accountId, signingPublicKey: input.signer.keys.signing.publicKey },
    signerSecretKey: input.signer.keys.signing.secretKey,
    teamKey: cc1.randomBytes(32),
    previousKey: cc1.randomBytes(32),
  });
  return teamKeyVersionToJson(record);
}

export function forgeGrant(input: {
  teamId?: string;
  member: { accountId: string; memberKeysVersion: number; keys: Pairs };
  teamKeyVersion: number;
  signer: { accountId: string; keys: Pairs };
  teamKey?: Uint8Array;
}) {
  return grantToJson(
    createGrant(cc1, {
      teamId: input.teamId ?? "team-1",
      accountId: input.member.accountId,
      memberKeysVersion: input.member.memberKeysVersion,
      teamKeyVersion: input.teamKeyVersion,
      memberSigningPublicKey: input.member.keys.signing.publicKey,
      memberEncryptionPublicKey: input.member.keys.encryption.publicKey,
      teamKey: input.teamKey ?? cc1.randomBytes(32),
      signer: { accountId: input.signer.accountId, signingPublicKey: input.signer.keys.signing.publicKey },
      signerSecretKey: input.signer.keys.signing.secretKey,
      createdAt: 1,
    }),
  );
}

/** A member keys record claiming `accountId`, self-signed by keys the attacker made. */
export function forgeMemberKeys(accountId: string, memberKeysVersion: number, keys: Pairs, previous?: Pairs) {
  return memberKeysToJson(
    createMemberKeys(
      cc1,
      { teamId: "team-1", accountId, memberKeysVersion, signingPublicKey: keys.signing.publicKey, encryptionPublicKey: keys.encryption.publicKey, createdAt: 1 },
      keys.signing.secretKey,
      previous?.signing.secretKey,
    ),
  );
}
