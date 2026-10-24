// team-state (§4.4): the newest team key version record this account verified.
import { unwrap, wrap, type Wrapped } from "../blocks/wrap.js";
import { Reader, bytes, enc, string, u32, u64, type Field } from "../encoding/canonical.js";
import type { JsonRecord } from "../encoding/json.js";
import type { Anchor } from "../encoding/link.js";
import { trustFailure } from "../errors.js";
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

export function parseTeamState(json: unknown, expected: TeamStateContext): TeamState {
  const { header, fields } = readRecord(json, TEAM_STATE, ["accountId", "teamId", "revision", "wrappedState"]);
  const record: TeamState = {
    ...header,
    accountId: fields.id("accountId"),
    teamId: fields.id("teamId"),
    // Below the largest safe integer, so the next write's revision stays exact.
    revision: fields.int("revision", 1, Number.MAX_SAFE_INTEGER - 1),
    wrappedState: readWrapped(fields, "wrappedState", header.suite, STATE_MAX + header.suite.sizes.tag),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/** A state that doesn't open is tampering, never ignored (§4.4): `TRUST_FAILURE` (`state_unreadable`). */
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
