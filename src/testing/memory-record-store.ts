// An honest in-memory key store applying every rule of protocol §11 (D-24, D-25). Not persistent.
import { StoreConflictError } from "../errors.js";
import type { RecordKey, RecordQuery, RecordStore, WireRecord, WriteOp } from "../ports.js";

interface Entry {
  readonly key: RecordKey;
  readonly record: WireRecord;
}

/** Identity fields of each record type, in identity order (§11). */
const IDENTITY: Record<RecordKey["type"], readonly string[]> = {
  "account-key-wrap": ["accountId", "accountKeyVersion", "method", "deviceId"],
  "member-keys": ["teamId", "accountId", "memberKeysVersion"],
  "member-keys-wrap": ["accountId", "teamId", "memberKeysVersion", "accountKeyVersion"],
  "team-state": ["accountId", "teamId"],
  "team-key-version": ["teamId", "version"],
  item: ["teamId", "itemId"],
  inbox: ["teamId", "inboxId"],
};

/** Writers keep a version record within this size (§2, D-34); a server refuses larger ones. */
const VERSION_RECORD_BYTES = 393_216;

/** Records served only to their own account (§11, server contract rule 1). */
const PRIVATE = new Set<RecordKey["type"]>(["account-key-wrap", "member-keys-wrap", "team-state"]);

const fieldsOf = (key: object) => key as Record<string, unknown>;
const keyString = (key: RecordKey) => JSON.stringify(Object.entries(key).sort(([a], [b]) => a.localeCompare(b)));
const clone = <T>(value: T): T => structuredClone(value);

class Forbidden extends Error {}

/**
 * The server: one shared state. Each client talks to it through a view bound to the
 * account it is signed in as (`as(accountId)`), or with no account (`anonymous()`).
 *
 * Each identity has at most one live record. Removed and replaced records, retired account key
 * versions and previous team state revisions go to an archive, no longer served and kept for the
 * restore window (rule 7, TH-36, TH-46, D-39, D-42).
 */
export class MemoryRecordStore {
  #live = new Map<string, Entry>();
  /** Archived records per identity, oldest first. */
  #archive = new Map<string, Entry[]>();
  #accountVersions = new Map<string, number>();

  /** A client signed in as `accountId`. */
  as(accountId: string): RecordStore {
    return this.#view(accountId);
  }

  /** A client with no account, for example a link holder reading an `item` record (§7.3). */
  anonymous(): RecordStore {
    return this.#view(null);
  }

  /** The archived records of one identity, oldest first, as the integration's support process would list them. */
  archived(key: RecordKey): WireRecord[] {
    return (this.#archive.get(keyString(key)) ?? []).map((e) => clone(e.record));
  }

  /**
   * Brings back an archived record (by default the newest), as the integration's support
   * process would (TH-36). The live record, if any, is archived, never dropped.
   */
  restore(key: RecordKey, index?: number): void {
    const id = keyString(key);
    const archived = this.#archive.get(id) ?? [];
    const at = index ?? archived.length - 1;
    const chosen = archived[at];
    if (!chosen) return;
    archived.splice(at, 1);
    archiveLive(this.#live, this.#archive, id);
    this.#live.set(id, chosen);
  }

  /**
   * Makes an archived account key version current again, as the integration's support process
   * would after a takeover with a rotation (D-42): the account's live records of later versions are
   * archived, and the newest archived generation of each record of `version` is served again. Pick
   * an older generation of one record with `restore` afterwards.
   */
  restoreVersion(accountId: string, version: number): void {
    const current = this.#accountVersions.get(accountId);
    if (current === undefined || !Number.isSafeInteger(version) || version < 1 || version > current) throw new Error("no such version");
    for (const [id, entry] of [...this.#live]) {
      const k = fieldsOf(entry.key);
      if (k["accountId"] === accountId && typeof k["accountKeyVersion"] === "number" && k["accountKeyVersion"] > version) {
        archiveLive(this.#live, this.#archive, id);
      }
    }
    for (const [id, generations] of this.#archive) {
      const k = fieldsOf(generations[0]?.key ?? {});
      if (k["accountId"] === accountId && k["accountKeyVersion"] === version && !this.#live.has(id)) this.restore(generations[0]!.key);
    }
    this.#accountVersions.set(accountId, version);
  }

  /** Every record ever written, archived ones included: what a database thief would get. */
  dump(): WireRecord[] {
    return [...this.#live.values(), ...[...this.#archive.values()].flat()].map((e) => clone(e.record));
  }

  #view(caller: string | null): RecordStore {
    const canRead = (key: RecordKey) => !PRIVATE.has(key.type) || fieldsOf(key)["accountId"] === caller;
    return {
      get: async (key) => {
        if (!canRead(key)) throw new Forbidden("private record");
        const entry = this.#live.get(keyString(key));
        return entry ? clone(entry.record) : null;
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
    const matches = [...this.#live.values()].filter((entry) => {
      if (entry.key.type !== query.type) return false;
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

  /** Applies the batch to copies and swaps them in only if every rule holds (atomic). */
  #commit(ops: readonly WriteOp[], caller: string | null): void {
    const live = new Map(this.#live);
    const archive = new Map([...this.#archive].map(([k, list]) => [k, [...list]]));
    const versions = new Map(this.#accountVersions);
    const conflict = (why: string) => new StoreConflictError(why);
    const ownOnly = (key: RecordKey) => {
      if (PRIVATE.has(key.type) && fieldsOf(key)["accountId"] !== caller) throw new Forbidden("private record");
    };
    const touched = new Set<string>();
    const newVersions: { teamId: string; version: number }[] = [];
    const atCurrentVersion: { teamId: string; version: unknown }[] = [];

    for (const op of ops) {
      if (op.op !== "set-account-key-version") {
        // Integration guide: a batch never touches one key twice.
        const id = keyString(op.key);
        if (touched.has(id)) throw conflict("key written twice in one batch");
        touched.add(id);
      }
      switch (op.op) {
        case "create": {
          ownOnly(op.key);
          checkIdentity(op.key, op.record);
          if (live.has(keyString(op.key))) throw conflict("write-once");
          if (op.key.type === "team-key-version") {
            const { teamId, version } = op.key;
            const before = currentTeamKeyVersion(teamId, this.#live);
            if (version !== before + 1 || newVersions.some((v) => v.teamId === teamId)) {
              throw conflict("version must be current + 1");
            }
            if (new TextEncoder().encode(JSON.stringify(op.record)).length > VERSION_RECORD_BYTES) throw conflict("record too large");
            newVersions.push({ teamId, version });
          }
          if (op.key.type === "member-keys") {
            // §11 (D-43): only the account publishes its keys, and their versions are consecutive.
            const { teamId, accountId, memberKeysVersion } = op.key;
            if (accountId !== caller) throw new Forbidden("member keys of another account");
            const newest = Math.max(
              0,
              ...[...live.values()]
                .map((e) => fieldsOf(e.key))
                .filter((k) => k["type"] === "member-keys" && k["teamId"] === teamId && k["accountId"] === accountId)
                .map((k) => k["memberKeysVersion"] as number),
            );
            if (memberKeysVersion !== newest + 1) throw conflict("member keys version must be the newest + 1");
          }
          if (op.key.type === "item" || op.key.type === "inbox") {
            atCurrentVersion.push({ teamId: op.key.teamId, version: op.record["teamKeyVersion"] });
          }
          live.set(keyString(op.key), { key: clone(op.key), record: clone(op.record) });
          break;
        }
        case "compare-and-set": {
          ownOnly(op.key);
          checkIdentity(op.key, op.record);
          const entry = live.get(keyString(op.key));
          const revision = entry ? (entry.record["revision"] as number) : null;
          if (revision !== op.expectedRevision) throw conflict("revision changed");
          if (op.record["revision"] !== (revision ?? 0) + 1) throw conflict("revision must increase by one");
          // Rule 7 (D-42): the previous revision is archived, so a garbage write can be undone.
          archiveLive(live, archive, keyString(op.key));
          live.set(keyString(op.key), { key: clone(op.key), record: clone(op.record) });
          break;
        }
        case "replace": {
          ownOnly(op.key);
          if (op.key.type !== "account-key-wrap" && op.key.type !== "member-keys-wrap") throw new Forbidden("only wraps are replaced");
          checkIdentity(op.key, op.record);
          const id = keyString(op.key);
          if (!live.has(id)) throw conflict("nothing to replace");
          archiveLive(live, archive, id);
          live.set(id, { key: clone(op.key), record: clone(op.record) });
          break;
        }
        case "delete": {
          // Rule 3: only the caller's own private records; public key records stay, so nobody re-creates them.
          if (!PRIVATE.has(op.key.type)) throw new Forbidden("public records are never deleted");
          ownOnly(op.key);
          archiveLive(live, archive, keyString(op.key));
          break;
        }
        case "set-account-key-version": {
          if (op.accountId !== caller) throw new Forbidden("private record");
          const current = versions.get(op.accountId) ?? null;
          if (current !== op.expected || op.accountKeyVersion !== (current ?? 0) + 1) throw conflict("account key version");
          versions.set(op.accountId, op.accountKeyVersion);
          // Rule 7: a retired account key version's wraps stop being served.
          for (const [id, entry] of [...live]) {
            const k = fieldsOf(entry.key);
            const retired = k["accountId"] === op.accountId && current !== null && k["accountKeyVersion"] === current;
            if (retired && (entry.key.type === "account-key-wrap" || entry.key.type === "member-keys-wrap")) archiveLive(live, archive, id);
          }
          break;
        }
      }
    }

    // Items and inboxes only at the current version, the batch's new version included (§11).
    for (const { teamId, version } of atCurrentVersion) {
      if (version !== currentTeamKeyVersion(teamId, live)) throw conflict("not the current team key version");
    }

    this.#live = live;
    this.#archive = archive;
    this.#accountVersions = versions;
  }
}

/** Moves the live record under `id`, if any, to the end of its archive. */
function archiveLive(live: Map<string, Entry>, archive: Map<string, Entry[]>, id: string) {
  const entry = live.get(id);
  if (!entry) return;
  live.delete(id);
  archive.set(id, [...(archive.get(id) ?? []), entry]);
}

function currentTeamKeyVersion(teamId: string, live: Map<string, Entry>): number {
  let current = 0;
  for (const entry of live.values()) {
    const k = fieldsOf(entry.key);
    if (entry.key.type === "team-key-version" && k["teamId"] === teamId) current = Math.max(current, k["version"] as number);
  }
  return current;
}

/** A conforming server stores a record only under its own identity. */
function checkIdentity(key: RecordKey, record: WireRecord) {
  if (record["type"] !== key.type) throw new StoreConflictError("type");
  for (const field of IDENTITY[key.type]) {
    if (fieldsOf(key)[field] !== record[field]) throw new StoreConflictError(`identity field ${field}`);
  }
}
