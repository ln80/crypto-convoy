// team-state (§4.4): the newest team key version record this account verified.
import { unwrap, wrap, type Wrapped } from "../blocks/wrap.js";
import { Reader, bytes, enc, string, u32, u64, type Field } from "../encoding/canonical.js";
import type { JsonRecord } from "../encoding/json.js";
import type { Anchor } from "../encoding/link.js";
import { malformed, trustFailure } from "../errors.js";
import type { Suite } from "../suites/suite.js";
import { expectContext, readRecord, readWrapped, writeHeader, writeWrapped, type RecordHeader } from "./common.js";

export const TEAM_STATE = "team-state";

export interface TeamStateContext {
  readonly accountId: string;
  readonly teamId: string;
}

export interface TeamState extends RecordHeader, TeamStateContext {
  readonly revision: number;
  readonly wrappedState: Wrapped;
}

const adFields = (c: TeamStateContext, revision: number): Field[] => [string(c.accountId), string(c.teamId), u64(revision)];
const STATE_MAX = 4 + 4 + 32;

export function createTeamState(
  suite: Suite,
  context: TeamStateContext,
  revision: number,
  teamStateKey: Uint8Array,
  anchor: Anchor,
): TeamState {
  const state = enc(u32(anchor.version), bytes(anchor.hash));
  return { v: 1, suite, ...context, revision, wrappedState: wrap(suite, teamStateKey, "team-state", adFields(context, revision), state) };
}

/** The highest revision a reader accepts: the next write's revision stays an exact integer. */
const REVISION_MAX = Number.MAX_SAFE_INTEGER - 1;

/**
 * The `revision`, read before the version (§4.4, §8, D-62): it means the same in every `v`, so a record
 * this library can't otherwise read can still be replaced by compare-and-set. Throws `MALFORMED_RECORD`.
 */
export function readTeamStateRevision(json: unknown): number {
  const revision = typeof json === "object" && json !== null ? (json as Record<string, unknown>)["revision"] : undefined;
  if (typeof revision !== "number" || !Number.isInteger(revision) || revision < 1 || revision > REVISION_MAX) throw malformed();
  return revision;
}

export function parseTeamState(json: unknown, expected: TeamStateContext): TeamState {
  const { header, fields } = readRecord(json, TEAM_STATE, ["accountId", "teamId", "revision", "wrappedState"]);
  const record: TeamState = {
    ...header,
    accountId: fields.id("accountId"),
    teamId: fields.id("teamId"),
    revision: fields.int("revision", 1, REVISION_MAX),
    wrappedState: readWrapped(fields, "wrappedState", header.suite, STATE_MAX + header.suite.sizes.tag),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/** A state that doesn't open is `TRUST_FAILURE` (`state_unreadable`); the caller decides whether that is absent (§4.4, D-62). */
export function openTeamState(record: TeamState, teamStateKey: Uint8Array): Anchor {
  try {
    const reader = new Reader(unwrap(record.suite, teamStateKey, "team-state", adFields(record, record.revision), record.wrappedState));
    const anchor = { version: reader.u32(), hash: reader.bytes() };
    reader.end();
    if (anchor.version < 1 || anchor.hash.length !== record.suite.sizes.hash) throw new Error("bad anchor");
    return anchor;
  } catch {
    throw trustFailure("state_unreadable");
  }
}

export function teamStateToJson(record: TeamState): JsonRecord {
  return {
    ...writeHeader(TEAM_STATE, record.suite),
    accountId: record.accountId,
    teamId: record.teamId,
    revision: record.revision,
    wrappedState: writeWrapped(record.wrappedState),
  };
}
