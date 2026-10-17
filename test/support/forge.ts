// Records an attacker could build: with stolen or own keys, outside the library's checks.
import { openBundles } from "../../src/account/member-custody.js";
import { vaultInternals, type Vault } from "../../src/account/vault.js";
import { createGrant, grantToJson, openGrant, parseGrant } from "../../src/records/grant.js";
import { createMemberKeys, keysHash, memberKeysToJson, type MemberKeys } from "../../src/records/member-keys.js";
import { bundleKeyPairs, generateBundle } from "../../src/records/member-keys-wrap.js";
import {
  createTeamKeyVersion,
  openRosterEntry,
  parseTeamKeyVersion,
  recordHash,
  rosterEntryOf,
  teamKeyVersionToJson,
} from "../../src/records/team-key-version.js";
import type { RecordStore } from "../../src/ports.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import type { KeyPair } from "../../src/suites/suite.js";
import type { MemberBundle } from "../../src/team/context.js";

/** Keys a member holds (AS-07): their newest bundle for the team. */
export async function bundleOf(vault: Vault, teamId = "team-1"): Promise<MemberBundle> {
  return (await openBundles(vaultInternals(vault).ports, vaultInternals(vault).account(), teamId))[0]!;
}

/** Fresh keys with no member keys record behind them. */
export function strangerKeys() {
  return bundleKeyPairs(cc1, generateBundle(cc1));
}

type Pairs = MemberBundle["pairs"];

/** Someone's keys as a forged record names them: `published` gives the exact keys hash, else the hash of keys with a random recovery key. */
type Named = { accountId: string; keys: Pairs; memberKeysVersion?: number; published?: MemberKeys };

function hashOf(teamId: string, who: Named): Uint8Array {
  return keysHash(
    cc1,
    who.published ?? {
      teamId,
      accountId: who.accountId,
      memberKeysVersion: who.memberKeysVersion ?? 1,
      signingPublicKey: who.keys.signing.publicKey,
      encryptionPublicKey: who.keys.encryption.publicKey,
      recoveryPublicKey: cc1.signingKeyPair(cc1.randomBytes(32)).publicKey,
    },
  );
}

export async function versionRecord(store: RecordStore, teamId: string, version: number) {
  return parseTeamKeyVersion(await store.get({ type: "team-key-version", teamId, version }), { teamId });
}

/** A version record signed with `signer` keys, chained after the served record `version − 1`. */
export async function forgeVersion(
  store: RecordStore,
  input: { teamId?: string; version: number; owners: Named[]; signer: Named; roster?: Named[] },
) {
  const teamId = input.teamId ?? "team-1";
  const previous = await versionRecord(store, teamId, input.version - 1);
  const record = createTeamKeyVersion(cc1, {
    teamId,
    version: input.version,
    prevHash: recordHash(previous),
    owners: input.owners.map((o) => ({ accountId: o.accountId, signingPublicKey: o.keys.signing.publicKey })),
    // By default the owners and the signer hold the version, as §4.5 rule 5 asks.
    roster: (input.roster ?? [...input.owners, ...(input.owners.some((o) => o.accountId === input.signer.accountId) ? [] : [input.signer])]).map(
      (who) => ({
        accountId: who.accountId,
        memberKeysVersion: who.published?.memberKeysVersion ?? who.memberKeysVersion ?? 1,
        keysHash: hashOf(teamId, who),
        encryptionPublicKey: who.keys.encryption.publicKey,
      }),
    ),
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
  member: Named & { memberKeysVersion: number };
  teamKeyVersion: number;
  signer: { accountId: string; keys: Pairs };
  teamKey?: Uint8Array;
}) {
  const teamId = input.teamId ?? "team-1";
  return grantToJson(
    createGrant(cc1, {
      teamId,
      accountId: input.member.accountId,
      memberKeysVersion: input.member.memberKeysVersion,
      teamKeyVersion: input.teamKeyVersion,
      keysHash: hashOf(teamId, input.member),
      encryptionPublicKey: input.member.keys.encryption.publicKey,
      teamKey: input.teamKey ?? cc1.randomBytes(32),
      signer: { accountId: input.signer.accountId, signingPublicKey: input.signer.keys.signing.publicKey },
      signerSecretKey: input.signer.keys.signing.secretKey,
      createdAt: 1,
    }),
  );
}

/**
 * A member keys record claiming `accountId`, self-signed by keys the attacker made. `previous`
 * signs for continuity; `recovery` sets the recovery key and, with `recoverySigner`, a recovery signature.
 */
export function forgeMemberKeys(
  accountId: string,
  memberKeysVersion: number,
  keys: Pairs,
  previous?: Pairs,
  options: { recovery?: Uint8Array; recoverySigner?: KeyPair; invite?: { inviteId: string; secret: Uint8Array } } = {},
) {
  const recovery = options.recovery ?? options.recoverySigner?.publicKey ?? cc1.signingKeyPair(cc1.randomBytes(32)).publicKey;
  return memberKeysToJson(
    createMemberKeys(
      cc1,
      {
        teamId: "team-1", accountId, memberKeysVersion, signingPublicKey: keys.signing.publicKey,
        encryptionPublicKey: keys.encryption.publicKey, recoveryPublicKey: recovery, createdAt: 1,
      },
      keys.signing.secretKey,
      {
        ...(previous ? { previousSigningSecretKey: previous.signing.secretKey } : {}),
        ...(options.recoverySigner ? { recoverySigningSecretKey: options.recoverySigner.secretKey } : {}),
        ...(options.invite ? { invite: options.invite } : {}),
      },
    ),
  );
}

/**
 * What gives `accountId` team key `version`, as the store serves it: its roster entry, else its
 * newest grant (§4.5, §4.6). `open` uses the given encryption keys; `null` when it holds nothing.
 */
export async function accessOf(store: RecordStore, accountId: string, version: number, teamId = "team-1") {
  const record = await versionRecord(store, teamId, version);
  const entry = rosterEntryOf(record, accountId);
  if (entry) return { memberKeysVersion: entry.memberKeysVersion, open: (pair: KeyPair) => openRosterEntry(record, entry, pair) };
  const grants = (await store.list({ type: "grant", teamId, accountId, teamKeyVersion: version })).map((g) => parseGrant(g, { teamId }));
  const grant = grants.at(-1);
  return grant ? { memberKeysVersion: grant.memberKeysVersion, open: (pair: KeyPair) => openGrant(grant, pair) } : null;
}
