// A malicious server for adversarial tests: an honest store view with tamper hooks
// (testing guide: swap, replay, rollback, drop, fork, garbage, withhold).
import type { PartKey, RecordKey, RecordQuery, RecordStore, WriteOp } from "../../src/ports.js";

type Match = { type: string } & Record<string, unknown>;
const matches = (key: object, match: Match) =>
  Object.entries(match).every(([field, value]) => (key as Record<string, unknown>)[field] === value);
const recordMatches = (record: unknown, match: Match) =>
  typeof record === "object" && record !== null && matches(record, match);

export class TamperingStore implements RecordStore {
  #replacements: { match: Match; value: () => unknown }[] = [];
  #dropped: Match[] = [];
  #chainCuts = new Map<string, number>();
  #forks: { teamId: string; version: number; record: unknown }[] = [];
  #partReplacements: { match: Match; bytes: Uint8Array }[] = [];
  #commitFilter: ((ops: readonly WriteOp[]) => void) | undefined;
  #accountVersion: number | null | undefined;
  readonly commits: WriteOp[][] = [];

  constructor(readonly inner: RecordStore) {}

  /** Serves `value` for every record matching `match` (swap, replay, garbage). */
  replace(match: Match, value: unknown): this {
    this.#replacements.push({ match, value: () => structuredClone(value) });
    return this;
  }

  /** Withholds matching records: `get` returns null and `list` leaves them out. */
  drop(match: Match): this {
    this.#dropped.push(match);
    return this;
  }

  /** Serves the team key chain only up to `version` (rollback). */
  rollback(teamId: string, version: number): this {
    this.#chainCuts.set(teamId, version);
    return this;
  }

  /** Serves another record for one version of the chain (fork). */
  fork(teamId: string, version: number, record: unknown): this {
    this.#forks.push({ teamId, version, record });
    return this;
  }

  /** Serves this account key version instead of the current one. */
  accountVersion(version: number | null): this {
    this.#accountVersion = version;
    return this;
  }

  replacePart(match: Match, bytes: Uint8Array): this {
    this.#partReplacements.push({ match, bytes });
    return this;
  }

  /** Runs before each commit reaches the honest store; may throw to refuse or interrupt it. */
  onCommit(filter: (ops: readonly WriteOp[]) => void): this {
    this.#commitFilter = filter;
    return this;
  }

  reset(): this {
    this.#replacements = [];
    this.#dropped = [];
    this.#chainCuts.clear();
    this.#forks = [];
    this.#partReplacements = [];
    this.#commitFilter = undefined;
    this.#accountVersion = undefined;
    return this;
  }

  #tamper(record: unknown, key: object): unknown {
    if (this.#dropped.some((m) => matches(key, m) || recordMatches(record, m))) return null;
    const replacement = this.#replacements.find((r) => matches(key, r.match));
    if (replacement) return replacement.value();
    if ((key as RecordKey).type === "team-key-version") {
      const { teamId, version } = key as { teamId: string; version: number };
      const fork = this.#forks.find((f) => f.teamId === teamId && f.version === version);
      if (fork) return structuredClone(fork.record);
      const cut = this.#chainCuts.get(teamId);
      if (cut !== undefined && version > cut) return null;
    }
    return record;
  }

  async get(key: RecordKey) {
    return this.#tamper(await this.inner.get(key), key);
  }

  async getPart(key: PartKey) {
    const replacement = this.#partReplacements.find((r) => matches(key, r.match));
    return replacement ? replacement.bytes.slice() : this.inner.getPart(key);
  }

  async getPartStream(key: PartKey) {
    const bytes = await this.getPart(key);
    if (!bytes) return null;
    return (async function* () {
      yield bytes;
    })();
  }

  async list(query: RecordQuery) {
    const records = await this.inner.list(query);
    const out = records
      .map((record) => this.#tamper(record, { ...(record as object), type: query.type }))
      .filter((record) => record !== null);
    if (query.type === "team-key-version") {
      for (const fork of this.#forks) {
        const present = out.some((r) => (r as { version: number }).version === fork.version);
        if (fork.teamId === query.teamId && fork.version >= query.fromVersion && !present) out.push(structuredClone(fork.record) as object);
      }
      out.sort((a, b) => (a as { version: number }).version - (b as { version: number }).version);
    }
    return out;
  }

  async getAccountKeyVersion(accountId: string) {
    return this.#accountVersion !== undefined ? this.#accountVersion : this.inner.getAccountKeyVersion(accountId);
  }

  async commit(ops: readonly WriteOp[]) {
    this.#commitFilter?.(ops);
    await this.inner.commit(ops);
    this.commits.push([...ops]);
  }
}

/** Keeps every byte sequence sent to the server, for SP-01. */
export class RecordingStore implements RecordStore {
  readonly sent: Uint8Array[] = [];
  readonly sentText: string[] = [];

  constructor(readonly inner: RecordStore) {}

  get = (key: RecordKey) => this.inner.get(key);
  getPart = (key: PartKey) => this.inner.getPart(key);
  list = (query: RecordQuery) => this.inner.list(query);
  getAccountKeyVersion = (accountId: string) => this.inner.getAccountKeyVersion(accountId);

  async commit(ops: readonly WriteOp[]) {
    for (const op of ops) {
      if (op.op === "create-part") this.sent.push(op.bytes.slice());
      else this.sentText.push(JSON.stringify(op));
    }
    await this.inner.commit(ops);
  }
}
