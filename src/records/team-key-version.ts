// team-key-version (§4.5): one link of the team key chain, with that version's owners.
import { verifyPayload } from "../blocks/sign.js";
import { unwrap, wrap, wrappedHash, type Wrapped } from "../blocks/wrap.js";
import { bytes, list, optional, string, u32, u64 } from "../encoding/canonical.js";
import { LIMITS, b64, type JsonRecord } from "../encoding/json.js";
import { labelled } from "../encoding/labels.js";
import { decryptionFailed, malformed } from "../errors.js";
import { concat, utf8 } from "../internal/bytes.js";
import type { Suite } from "../suites/suite.js";
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

export interface TeamKeyVersion extends RecordHeader {
  readonly teamId: string;
  readonly version: number;
  readonly prevHash: Uint8Array;
  /** Sorted by `accountId` bytes, no duplicates, 1–64. */
  readonly owners: readonly SignerRef[];
  readonly wrappedPreviousKey: Wrapped | null;
  readonly signer: SignerRef;
  readonly createdAt: number;
  readonly signature: Uint8Array;
}

type Unsigned = Omit<TeamKeyVersion, "v" | "suite" | "signature">;

const KEY = 32;

/** The signed payload; the record hash is BLAKE2b-256 of it (§4.5). */
export function teamKeyVersionPayload(suite: Suite, r: Unsigned): Uint8Array {
  return labelled(
    "team-key-version",
    string(r.teamId),
    u32(r.version),
    bytes(r.prevHash),
    list(r.owners, (o) => concat(string(o.accountId), bytes(o.signingPublicKey))),
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

function checkOwners(owners: readonly SignerRef[]) {
  if (owners.length < 1 || owners.length > LIMITS.owners) throw malformed();
  for (let i = 1; i < owners.length; i++) {
    if (compareIds(owners[i - 1]!.accountId, owners[i]!.accountId) >= 0) throw malformed();
  }
}

export interface NewTeamKeyVersion {
  readonly teamId: string;
  readonly version: number;
  readonly prevHash: Uint8Array;
  readonly owners: readonly SignerRef[];
  readonly createdAt: number;
  readonly signer: SignerRef;
  readonly signerSecretKey: Uint8Array;
  readonly teamKey: Uint8Array;
  /** `teamKey_{n−1}`, absent for version 1. */
  readonly previousKey?: Uint8Array;
}

export function createTeamKeyVersion(suite: Suite, input: NewTeamKeyVersion): TeamKeyVersion {
  const owners = sortOwners(input.owners);
  checkOwners(owners);
  if ((input.version === 1) !== (input.previousKey === undefined)) throw malformed();
  const wrappedPreviousKey = input.previousKey
    ? wrap(suite, input.teamKey, "team-key-link", [string(input.teamId), u32(input.version)], input.previousKey)
    : null;
  const unsigned: Unsigned = {
    teamId: input.teamId,
    version: input.version,
    prevHash: input.prevHash,
    owners,
    wrappedPreviousKey,
    signer: input.signer,
    createdAt: input.createdAt,
  };
  const signature = suite.sign(input.signerSecretKey, teamKeyVersionPayload(suite, unsigned));
  return { v: 1, suite, ...unsigned, signature };
}

/** §8 steps 1–4 for one record: shape, version, context and its own signature. Chain rules are in team/chain. */
export function parseTeamKeyVersion(json: unknown, expected: { teamId: string; version?: number }): TeamKeyVersion {
  const { header, fields } = readRecord(json, TEAM_KEY_VERSION, [
    "teamId",
    "version",
    "prevHash",
    "owners",
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
    wrappedPreviousKey: fields.nullable("wrappedPreviousKey", (f, k) => readWrapped(f, k, suite, KEY + suite.sizes.tag)),
    signer: readSigner((json as JsonRecord)["signer"], suite),
    createdAt: fields.int("createdAt"),
    signature: fields.bytes("signature", suite.sizes.signature),
  };
  checkOwners(record.owners);
  if ((record.version === 1) !== (record.wrappedPreviousKey === null)) throw malformed();
  expectContext({ ...expected }, { ...record });
  verifyPayload(suite, record.signer.signingPublicKey, teamKeyVersionPayload(suite, record), record.signature);
  return record;
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
    wrappedPreviousKey: record.wrappedPreviousKey ? writeWrapped(record.wrappedPreviousKey) : null,
    signer: writeSigner(record.signer),
    createdAt: record.createdAt,
    signature: b64(record.signature),
  };
}
