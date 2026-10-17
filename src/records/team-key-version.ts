// team-key-version (§4.5): one link of the team key chain, with that version's owners.
import { open, seal } from "../blocks/seal.js";
import { verifyPayload } from "../blocks/sign.js";
import { unwrap, wrap, wrappedHash, type Wrapped } from "../blocks/wrap.js";
import { bytes, list, optional, string, u32, u64 } from "../encoding/canonical.js";
import { Fields, LIMITS, b64, type JsonRecord } from "../encoding/json.js";
import { labelled } from "../encoding/labels.js";
import { decryptionFailed, malformed } from "../errors.js";
import { concat, utf8 } from "../internal/bytes.js";
import type { KeyPair, Suite } from "../suites/suite.js";
import {
  expectContext,
  readRecord,
  readSigner,
  readWrapped,
  writeHeader,
  writeSigner,
  writeWrapped,
  type RecordHeader,
  type SignerRef,
} from "./common.js";

export const TEAM_KEY_VERSION = "team-key-version";

/** One account receiving the version: its keys, pinned by hash, and the key sealed to them (§4.5, D-34). */
export interface RosterEntry {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly keysHash: Uint8Array;
  readonly sealedTeamKey: Uint8Array;
}

export interface TeamKeyVersion extends RecordHeader {
  readonly teamId: string;
  readonly version: number;
  readonly prevHash: Uint8Array;
  /** Sorted by `accountId` bytes, no duplicates, 1–64. */
  readonly owners: readonly SignerRef[];
  /** Sorted by `accountId` bytes, no duplicates, 1–1,000. */
  readonly roster: readonly RosterEntry[];
  readonly wrappedPreviousKey: Wrapped | null;
  readonly signer: SignerRef;
  readonly createdAt: number;
  readonly signature: Uint8Array;
}

type Unsigned = Omit<TeamKeyVersion, "v" | "suite" | "signature">;

const KEY = 32;
const HASH = 32;
// Seal overhead 48, then the label "crypto-convoy/v1/roster-seal", u32 n, the keys hash and the key (§4.5).
const ROSTER_SEALED = 48 + (4 + 28) + 4 + (4 + HASH) + (4 + KEY);

const rosterContext = (version: number, keysHash: Uint8Array) => [u32(version), bytes(keysHash)];

/** The signed payload; the record hash is BLAKE2b-256 of it (§4.5). */
export function teamKeyVersionPayload(suite: Suite, r: Unsigned): Uint8Array {
  return labelled(
    "team-key-version",
    string(r.teamId),
    u32(r.version),
    bytes(r.prevHash),
    list(r.owners, (o) => concat(string(o.accountId), bytes(o.signingPublicKey))),
    list(r.roster, (e) => concat(string(e.accountId), u32(e.memberKeysVersion), bytes(e.keysHash), bytes(e.sealedTeamKey))),
    optional(r.wrappedPreviousKey, (w) => bytes(wrappedHash(suite, w))),
    string(r.signer.accountId),
    bytes(r.signer.signingPublicKey),
    u64(r.createdAt),
  );
}

export function recordHash(record: TeamKeyVersion): Uint8Array {
  return record.suite.hash(teamKeyVersionPayload(record.suite, record));
}

/** Byte order of the UTF-8 encoding, as the owner list requires. */
export function compareIds(a: string, b: string): number {
  const x = utf8(a);
  const y = utf8(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return x.length - y.length;
}

export function sortOwners(owners: readonly SignerRef[]): SignerRef[] {
  return [...owners].sort((a, b) => compareIds(a.accountId, b.accountId));
}

function checkSorted(items: readonly { accountId: string }[], max: number) {
  if (items.length < 1 || items.length > max) throw malformed();
  for (let i = 1; i < items.length; i++) {
    if (compareIds(items[i - 1]!.accountId, items[i]!.accountId) >= 0) throw malformed();
  }
}

/** A recipient of a new version: the keys the owner seals it to. */
export interface RosterRecipient {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly keysHash: Uint8Array;
  readonly encryptionPublicKey: Uint8Array;
}

export interface NewTeamKeyVersion {
  readonly teamId: string;
  readonly version: number;
  readonly prevHash: Uint8Array;
  readonly owners: readonly SignerRef[];
  readonly roster: readonly RosterRecipient[];
  readonly createdAt: number;
  readonly signer: SignerRef;
  readonly signerSecretKey: Uint8Array;
  readonly teamKey: Uint8Array;
  /** `teamKey_{n−1}`, absent for version 1. */
  readonly previousKey?: Uint8Array;
}

/** Throws `MALFORMED_RECORD` past the §2 bounds (owners, roster, record size) or for a low-order key. */
export function createTeamKeyVersion(suite: Suite, input: NewTeamKeyVersion): TeamKeyVersion {
  const owners = sortOwners(input.owners);
  checkSorted(owners, LIMITS.owners);
  const roster = [...input.roster]
    .sort((a, b) => compareIds(a.accountId, b.accountId))
    .map((r) => ({
      accountId: r.accountId,
      memberKeysVersion: r.memberKeysVersion,
      keysHash: r.keysHash,
      sealedTeamKey: seal(suite, r.encryptionPublicKey, "roster-seal", rosterContext(input.version, r.keysHash), input.teamKey),
    }));
  checkSorted(roster, LIMITS.roster);
  if ((input.version === 1) !== (input.previousKey === undefined)) throw malformed();
  const wrappedPreviousKey = input.previousKey
    ? wrap(suite, input.teamKey, "team-key-link", [string(input.teamId), u32(input.version)], input.previousKey)
    : null;
  const unsigned: Unsigned = {
    teamId: input.teamId,
    version: input.version,
    prevHash: input.prevHash,
    owners,
    roster,
    wrappedPreviousKey,
    signer: input.signer,
    createdAt: input.createdAt,
  };
  const signature = suite.sign(input.signerSecretKey, teamKeyVersionPayload(suite, unsigned));
  const record: TeamKeyVersion = { v: 1, suite, ...unsigned, signature };
  if (utf8(JSON.stringify(teamKeyVersionToJson(record))).length > LIMITS.versionRecordBytes) throw malformed();
  return record;
}

/** §8 steps 1–4 for one record: shape, version, context and its own signature. Chain rules are in team/chain. */
export function parseTeamKeyVersion(json: unknown, expected: { teamId: string; version?: number }): TeamKeyVersion {
  const { header, fields } = readRecord(json, TEAM_KEY_VERSION, [
    "teamId",
    "version",
    "prevHash",
    "owners",
    "roster",
    "wrappedPreviousKey",
    "signer",
    "createdAt",
    "signature",
  ]);
  const { suite } = header;
  const record: TeamKeyVersion = {
    ...header,
    teamId: fields.id("teamId"),
    version: fields.u32("version", 1),
    prevHash: fields.bytes("prevHash", suite.sizes.hash),
    owners: fields.list("owners", 1, LIMITS.owners, (o) => readSigner(o, suite)),
    roster: fields.list("roster", 1, LIMITS.roster, (e) => readRosterEntry(e, suite)),
    wrappedPreviousKey: fields.nullable("wrappedPreviousKey", (f, k) => readWrapped(f, k, suite, KEY + suite.sizes.tag)),
    signer: readSigner((json as JsonRecord)["signer"], suite),
    createdAt: fields.int("createdAt"),
    signature: fields.bytes("signature", suite.sizes.signature),
  };
  checkSorted(record.owners, LIMITS.owners);
  checkSorted(record.roster, LIMITS.roster);
  if ((record.version === 1) !== (record.wrappedPreviousKey === null)) throw malformed();
  expectContext({ ...expected }, { ...record });
  verifyPayload(suite, record.signer.signingPublicKey, teamKeyVersionPayload(suite, record), record.signature);
  return record;
}

function readRosterEntry(value: unknown, suite: Suite): RosterEntry {
  const fields = Fields.of(value, ["accountId", "memberKeysVersion", "keysHash", "sealedTeamKey"]);
  return {
    accountId: fields.id("accountId"),
    memberKeysVersion: fields.u32("memberKeysVersion", 1),
    keysHash: fields.bytes("keysHash", suite.sizes.hash),
    sealedTeamKey: fields.bytes("sealedTeamKey", ROSTER_SEALED),
  };
}

export function rosterEntryOf(record: TeamKeyVersion, accountId: string): RosterEntry | undefined {
  return record.roster.find((e) => e.accountId === accountId);
}

/** `teamKey_n` from the reader's own roster entry, whose keys hash the caller checked. Throws `DECRYPTION_FAILED`. */
export function openRosterEntry(record: TeamKeyVersion, entry: RosterEntry, encryption: KeyPair): Uint8Array {
  const teamKey = open(record.suite, encryption, "roster-seal", rosterContext(record.version, entry.keysHash), entry.sealedTeamKey);
  if (teamKey.length !== KEY) throw decryptionFailed();
  return teamKey;
}

/** `teamKey_{n−1}` from version n's link (§6.2). Throws `DECRYPTION_FAILED`. */
export function openPreviousKey(record: TeamKeyVersion, teamKey: Uint8Array): Uint8Array {
  if (!record.wrappedPreviousKey) throw decryptionFailed();
  const previous = unwrap(record.suite, teamKey, "team-key-link", [string(record.teamId), u32(record.version)], record.wrappedPreviousKey);
  if (previous.length !== KEY) throw decryptionFailed();
  return previous;
}

export function teamKeyVersionToJson(record: TeamKeyVersion): JsonRecord {
  return {
    ...writeHeader(TEAM_KEY_VERSION, record.suite),
    teamId: record.teamId,
    version: record.version,
    prevHash: b64(record.prevHash),
    owners: record.owners.map(writeSigner),
    roster: record.roster.map((e) => ({
      accountId: e.accountId,
      memberKeysVersion: e.memberKeysVersion,
      keysHash: b64(e.keysHash),
      sealedTeamKey: b64(e.sealedTeamKey),
    })),
    wrappedPreviousKey: record.wrappedPreviousKey ? writeWrapped(record.wrappedPreviousKey) : null,
    signer: writeSigner(record.signer),
    createdAt: record.createdAt,
    signature: b64(record.signature),
  };
}
