// An honest in-memory server applying every rule of protocol §11 (D-24). Not persistent.
import { StoreConflictError } from "../errors.js";
import type { PartKey, RecordKey, RecordQuery, RecordStore, WireRecord, WriteOp } from "../ports.js";

interface Entry {
  readonly key: RecordKey;
  readonly record: WireRecord;
  /** Soft delete: no longer served, kept for the restore window (TH-36). */
  deleted: boolean;
}

/** Identity fields of each record type, in identity order (§11). */
const IDENTITY: Record<RecordKey["type"], readonly string[]> = {
  "account-key-wrap": ["accountId", "accountKeyVersion", "method", "deviceId"],
  "member-keys": ["teamId", "accountId", "memberKeysVersion"],
  "member-keys-wrap": ["accountId", "teamId", "memberKeysVersion", "accountKeyVersion"],
  "team-state": ["accountId", "teamId"],
  "team-key-version": ["teamId", "version"],
  grant: ["teamId", "accountId", "memberKeysVersion", "teamKeyVersion"],
  item: ["teamId", "itemId"],
  inbox: ["teamId", "inboxId"],
  submission: ["teamId", "inboxId", "submissionId"],
};

/** Records served only to their own account (§11, server contract rule 1). */
const PRIVATE = new Set<RecordKey["type"]>(["account-key-wrap", "member-keys-wrap", "team-state"]);

const fieldsOf = (key: object) => key as Record<string, unknown>;
const keyString = (key: RecordKey | PartKey) => JSON.stringify(Object.entries(key).sort(([a], [b]) => a.localeCompare(b)));
const clone = <T>(value: T): T => structuredClone(value);

class Forbidden extends Error {}

/**
 * The server: one shared state. Each client talks to it through a view bound to the
 * account it is signed in as (`as(accountId)`), or with no account (`anonymous()`).
 */
export class MemoryRecordStore {
  readonly #records = new Map<string, Entry>();
  readonly #parts = new Map<string, Uint8Array>();
  readonly #accountVersions = new Map<string, number>();

  /** A client signed in as `accountId`. */
  as(accountId: string): RecordStore {
    return this.#view(accountId);
  }

  /** A client with no account: share links and inbox senders. */
  anonymous(): RecordStore {
    return this.#view(null);
  }

  /** Brings back a soft-deleted record, as the integration's support process would (TH-36). */
  restore(key: RecordKey): void {
    const entry = this.#records.get(keyString(key));
    if (entry) entry.deleted = false;
  }

  /** Every record ever written, deleted ones included: what a database thief would get. */
  dump(): { records: WireRecord[]; parts: Uint8Array[] } {
    return { records: [...this.#records.values()].map((e) => clone(e.record)), parts: [...this.#parts.values()].map(clone) };
  }

  #view(caller: string | null): RecordStore {
    const canRead = (key: RecordKey) => !PRIVATE.has(key.type) || fieldsOf(key)["accountId"] === caller;
    return {
      get: async (key) => {
        if (!canRead(key)) throw new Forbidden("private record");
        const entry = this.#records.get(keyString(key));
        return entry && !entry.deleted ? clone(entry.record) : null;
      },
      getPart: async (key) => {
        const part = this.#parts.get(keyString(key));
        return part ? part.slice() : null;
      },
      getPartStream: async (key) => {
        const part = this.#parts.get(keyString(key));
        if (!part) return null;
        return (async function* () {
          for (let offset = 0; offset < part.length; offset += 1 << 20) yield part.slice(offset, offset + (1 << 20));
        })();
      },
      list: async (query) => this.#list(query, caller),
      getAccountKeyVersion: async (accountId) => {
        if (accountId !== caller) throw new Forbidden("private record");
        return this.#accountVersions.get(accountId) ?? null;
      },
      commit: async (ops) => this.#commit(ops, caller),
    };
  }

  #list(query: RecordQuery, caller: string | null): WireRecord[] {
    const q = fieldsOf(query);
    if (PRIVATE.has(query.type) && q["accountId"] !== caller) throw new Forbidden("private record");
    const matches = [...this.#records.values()].filter((entry) => {
      if (entry.deleted || entry.key.type !== query.type) return false;
      const k = fieldsOf(entry.key);
      for (const [field, value] of Object.entries(q)) {
        if (field === "type" || value === undefined) continue;
        if (field === "fromVersion" ? (k["version"] as number) < (value as number) : k[field] !== value) return false;
      }
      return true;
    });
    const order = IDENTITY[query.type];
    matches.sort((a, b) => {
      for (const field of order) {
        const x = fieldsOf(a.key)[field] as string | number | undefined;
        const y = fieldsOf(b.key)[field] as string | number | undefined;
        if (x !== y) return (x ?? "") < (y ?? "") ? -1 : 1;
      }
      return 0;
    });
    return matches.map((e) => clone(e.record));
  }

  #currentTeamKeyVersion(teamId: string, records: Map<string, Entry>): number {
    let current = 0;
    for (const entry of records.values()) {
      const k = fieldsOf(entry.key);
      if (entry.key.type === "team-key-version" && k["teamId"] === teamId && !entry.deleted) {
        current = Math.max(current, k["version"] as number);
      }
    }
    return current;
  }

  /** Applies the batch to copies and swaps them in only if every rule holds (atomic). */
  #commit(ops: readonly WriteOp[], caller: string | null): void {
    const records = new Map([...this.#records].map(([k, e]) => [k, { ...e }]));
    const parts = new Map(this.#parts);
    const versions = new Map(this.#accountVersions);
    const conflict = (why: string) => new StoreConflictError(why);
    const ownOnly = (key: RecordKey) => {
      if (PRIVATE.has(key.type) && fieldsOf(key)["accountId"] !== caller) throw new Forbidden("private record");
    };
    const live = (key: RecordKey) => {
      const entry = records.get(keyString(key));
      return entry && !entry.deleted ? entry : undefined;
    };
    const newVersions: { teamId: string; version: number; signer: string }[] = [];
    const atCurrentVersion: { teamId: string; version: unknown }[] = [];

    for (const op of ops) {
      switch (op.op) {
        case "create": {
          ownOnly(op.key);
          checkIdentity(op.key, op.record);
          if (live(op.key)) throw conflict("write-once");
          if (op.key.type === "team-key-version") {
            const { teamId, version } = op.key;
            const before = this.#currentTeamKeyVersion(teamId, this.#records);
            if (version !== before + 1 || newVersions.some((v) => v.teamId === teamId)) {
              throw conflict("version must be current + 1");
            }
            const signer = fieldsOf(op.record["signer"] as object)["accountId"] as string;
            newVersions.push({ teamId, version, signer });
          }
          if (op.key.type === "grant" || op.key.type === "item" || op.key.type === "inbox") {
            atCurrentVersion.push({ teamId: op.key.teamId, version: op.record["teamKeyVersion"] });
          }
          records.set(keyString(op.key), { key: clone(op.key), record: clone(op.record), deleted: false });
          break;
        }
        case "create-part": {
          const parent: RecordKey =
            op.key.type === "item-part"
              ? { type: "item", teamId: op.key.teamId, itemId: op.key.itemId }
              : { type: "submission", teamId: op.key.teamId, inboxId: op.key.inboxId, submissionId: op.key.submissionId };
          if (!live(parent)) throw conflict("part before its record");
          if (parts.has(keyString(op.key))) throw conflict("write-once");
          parts.set(keyString(op.key), op.bytes.slice());
          break;
        }
        case "compare-and-set": {
          ownOnly(op.key);
          checkIdentity(op.key, op.record);
          const entry = live(op.key);
          const revision = entry ? (entry.record["revision"] as number) : null;
          if (revision !== op.expectedRevision) throw conflict("revision changed");
          if (op.record["revision"] !== (revision ?? 0) + 1) throw conflict("revision must increase by one");
          records.set(keyString(op.key), { key: clone(op.key), record: clone(op.record), deleted: false });
          break;
        }
        case "delete": {
          ownOnly(op.key);
          const entry = live(op.key);
          if (entry) entry.deleted = true;
          break;
        }
        case "set-account-key-version": {
          if (op.accountId !== caller) throw new Forbidden("private record");
          const current = versions.get(op.accountId) ?? null;
          if (current !== op.expected || op.accountKeyVersion !== (current ?? 0) + 1) throw conflict("account key version");
          versions.set(op.accountId, op.accountKeyVersion);
          // Rule 7: a retired account key version's wraps stop being served.
          for (const entry of records.values()) {
            const k = fieldsOf(entry.key);
            const retired = k["accountId"] === op.accountId && current !== null && k["accountKeyVersion"] === current;
            if (retired && (entry.key.type === "account-key-wrap" || entry.key.type === "member-keys-wrap")) entry.deleted = true;
          }
          break;
        }
      }
    }

    // Grants, items and inboxes only at the current version, the batch's new version included (§11).
    for (const { teamId, version } of atCurrentVersion) {
      if (version !== this.#currentTeamKeyVersion(teamId, records)) throw conflict("not the current team key version");
    }

    // A new team key version is stored atomically with its signer's grant (§11).
    for (const { teamId, version, signer } of newVersions) {
      const hasGrant = [...records.values()].some((e) => {
        const k = fieldsOf(e.key);
        return !e.deleted && e.key.type === "grant" && k["teamId"] === teamId && k["teamKeyVersion"] === version && k["accountId"] === signer;
      });
      if (!hasGrant) throw conflict("version without its signer's grant");
    }

    this.#records.clear();
    for (const [k, e] of records) this.#records.set(k, e);
    this.#parts.clear();
    for (const [k, p] of parts) this.#parts.set(k, p);
    this.#accountVersions.clear();
    for (const [k, v] of versions) this.#accountVersions.set(k, v);
  }
}

/** A conforming server stores a record only under its own identity. */
function checkIdentity(key: RecordKey, record: WireRecord) {
  if (record["type"] !== key.type) throw new StoreConflictError("type");
  for (const field of IDENTITY[key.type]) {
    if (fieldsOf(key)[field] !== record[field]) throw new StoreConflictError(`identity field ${field}`);
  }
}
