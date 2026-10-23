/**
 * The testing kit's store applies the server contract of protocol §11 (D-24).
 * These cases double as the contract a production server must pass.
 */
import { describe, expect, it } from "vitest";
import { RateLimitedError, StoreConflictError } from "../../src/errors.js";
import type { RecordKey, WireRecord, WriteOp } from "../../src/ports.js";
import { FakeOprfServer, MemoryRecordStore } from "../../src/testing/index.js";
import { sampleRecords } from "../support/records.js";

const sample = sampleRecords();
const r = sample.records;
const keyOf = (record: WireRecord): RecordKey => {
  const { type } = record as { type: RecordKey["type"] };
  const pick = (...fields: string[]) => Object.fromEntries([["type", type], ...fields.map((f) => [f, record[f]])]);
  switch (type) {
    case "team-key-version": return pick("teamId", "version") as RecordKey;
    case "item": return pick("teamId", "itemId") as RecordKey;
    case "inbox": return pick("teamId", "inboxId") as RecordKey;
    case "member-keys": return pick("teamId", "accountId", "memberKeysVersion") as RecordKey;
    case "account-key-wrap": return pick("accountId", "accountKeyVersion", "method") as RecordKey;
    default: throw new Error(type);
  }
};
const create = (record: WireRecord): WriteOp => ({ op: "create", key: keyOf(record), record });
const replace = (record: WireRecord): WriteOp => ({ op: "replace", key: keyOf(record) as Extract<RecordKey, { type: "account-key-wrap" }>, record });
const conflict = expect.any(StoreConflictError);

function teamStore() {
  const server = new MemoryRecordStore();
  return { server, alice: server.as("alice") };
}

describe("server contract (§11)", () => {
  it("creates a team with its version 1 alone: the record carries its roster (D-34)", async () => {
    const { alice } = teamStore();
    await expect(alice.commit([create({ ...r["team-key-version"], version: 2 })])).rejects.toEqual(conflict);
    await alice.commit([create(r["team-key-version"])]);
    expect(await alice.list({ type: "team-key-version", teamId: "team-1", fromVersion: 1 })).toHaveLength(1);
  });

  it("refuses a version record over 384 KiB", async () => {
    const { alice } = teamStore();
    const huge = { ...r["team-key-version"], padding: "x".repeat(393_216) };
    await expect(alice.commit([create(huge)])).rejects.toEqual(conflict);
  });

  it("never overwrites a write-once record", async () => {
    const { alice } = teamStore();
    await alice.commit([create(r["member-keys"])]);
    await expect(alice.commit([create(r["member-keys"])])).rejects.toEqual(conflict);
  });

  it("accepts a new version only as current + 1", async () => {
    const { alice } = teamStore();
    const v3 = { ...r["team-key-version"], version: 3 };
    await expect(alice.commit([create(v3)])).rejects.toEqual(conflict);
  });

  it("accepts items and inboxes only at the current version", async () => {
    const { alice } = teamStore();
    await alice.commit([create(r["team-key-version"])]);
    await alice.commit([create(r.item), create(r.inbox)]);
    await expect(alice.commit([create({ ...r.item, itemId: "item-2", teamKeyVersion: 2 })])).rejects.toEqual(conflict);
    await expect(alice.commit([create({ ...r.inbox, inboxId: "inbox-2", teamKeyVersion: 2 })])).rejects.toEqual(conflict);
  });

  it("stores a record only under its own identity", async () => {
    const { alice } = teamStore();
    await expect(alice.commit([{ op: "create", key: { type: "member-keys", teamId: "team-2", accountId: "alice", memberKeysVersion: 1 }, record: r["member-keys"] }])).rejects.toEqual(conflict);
  });

  it("compares and sets team states on their revision", async () => {
    const { alice } = teamStore();
    const key = { type: "team-state", accountId: "alice", teamId: "team-1" } as const;
    const state = r["team-state"];
    await alice.commit([{ op: "compare-and-set", key, expectedRevision: null, record: state }]);
    await expect(alice.commit([{ op: "compare-and-set", key, expectedRevision: null, record: state }])).rejects.toEqual(conflict);
    await expect(alice.commit([{ op: "compare-and-set", key, expectedRevision: 1, record: state }])).rejects.toEqual(conflict);
    await alice.commit([{ op: "compare-and-set", key, expectedRevision: 1, record: { ...state, revision: 2 } }]);
  });

  it("serves private records only to their account", async () => {
    const server = new MemoryRecordStore();
    const wrap = r["account-key-wrap"];
    await server.as("alice").commit([create(wrap)]);
    await expect(server.as("bob").get(keyOf(wrap))).rejects.toThrow();
    await expect(server.anonymous().get(keyOf(wrap))).rejects.toThrow();
    await expect(server.as("bob").commit([create(wrap)])).rejects.toThrow();
    expect(await server.as("alice").get(keyOf(wrap))).toEqual(wrap);
  });

  it("switches the account key version atomically and retires the old version's wraps", async () => {
    const { server, alice } = teamStore();
    const wrap = r["account-key-wrap"];
    await alice.commit([create(wrap), { op: "set-account-key-version", accountId: "alice", expected: null, accountKeyVersion: 1 }]);
    await expect(alice.commit([{ op: "set-account-key-version", accountId: "alice", expected: null, accountKeyVersion: 2 }])).rejects.toEqual(conflict);
    await alice.commit([{ op: "set-account-key-version", accountId: "alice", expected: 1, accountKeyVersion: 2 }]);
    expect(await alice.get(keyOf(wrap))).toBeNull();
    server.restore(keyOf(wrap));
    expect(await alice.get(keyOf(wrap))).toEqual(wrap);
  });

  it("archives a deleted record: no longer served, and restorable (TH-36)", async () => {
    const { server, alice } = teamStore();
    const wrap = r["account-key-wrap"];
    await alice.commit([create(wrap)]);
    await alice.commit([{ op: "delete", key: keyOf(wrap) }]);
    expect(await alice.get(keyOf(wrap))).toBeNull();
    expect(server.archived(keyOf(wrap))).toEqual([wrap]);
    server.restore(keyOf(wrap));
    expect(await alice.get(keyOf(wrap))).toEqual(wrap);
    expect(server.archived(keyOf(wrap))).toEqual([]);
  });

  it("replaces a live wrap in place and archives the old one; restoring archives the live one (D-39)", async () => {
    const { server, alice } = teamStore();
    const wrap = r["account-key-wrap"];
    const garbage = { ...wrap, createdAt: 1 };
    await alice.commit([create(wrap)]);
    await alice.commit([replace(garbage)]);
    expect(await alice.get(keyOf(wrap))).toEqual(garbage);
    expect(server.archived(keyOf(wrap))).toEqual([wrap]);
    server.restore(keyOf(wrap));
    expect(await alice.get(keyOf(wrap))).toEqual(wrap);
    expect(server.archived(keyOf(wrap))).toEqual([garbage]);
    expect(server.dump()).toEqual(expect.arrayContaining([wrap, garbage]));
  });

  it("restores a chosen generation after several replacements", async () => {
    const { server, alice } = teamStore();
    const wrap = r["account-key-wrap"];
    await alice.commit([create(wrap)]);
    await alice.commit([replace({ ...wrap, createdAt: 1 })]);
    await alice.commit([replace({ ...wrap, createdAt: 2 })]);
    server.restore(keyOf(wrap), 0);
    expect(await alice.get(keyOf(wrap))).toEqual(wrap);
    expect(server.archived(keyOf(wrap))).toEqual([{ ...wrap, createdAt: 1 }, { ...wrap, createdAt: 2 }]);
  });

  it("replaces only a live wrap, and only wraps", async () => {
    const { alice } = teamStore();
    const wrap = r["account-key-wrap"];
    await expect(alice.commit([replace(wrap)])).rejects.toEqual(conflict);
    const state = r["team-state"];
    await expect(
      alice.commit([{ op: "replace", key: { type: "team-state", accountId: "alice", teamId: "team-1" }, record: state } as unknown as WriteOp]),
    ).rejects.toThrow();
  });

  it("refuses a batch that touches one key twice, and leaves the archive unchanged", async () => {
    const { server, alice } = teamStore();
    const wrap = r["account-key-wrap"];
    await alice.commit([create(wrap)]);
    await expect(alice.commit([{ op: "delete", key: keyOf(wrap) }, create(wrap)])).rejects.toEqual(conflict);
    expect(await alice.get(keyOf(wrap))).toEqual(wrap);
    expect(server.archived(keyOf(wrap))).toEqual([]);
  });
});

describe("fake OPRF server (§5.1)", () => {
  it("counts every evaluation in one budget, whatever its purpose", async () => {
    const oprf = new FakeOprfServer({ budget: 2 });
    const blinded = (await import("@noble/curves/ed25519.js")).ristretto255_oprf.oprf.blind(new Uint8Array(32)).blinded;
    await oprf.evaluate({ accountId: "a", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
    await oprf.evaluate({ accountId: "a", blindedElement: blinded, oprfKeyId: 1, purpose: "enroll" });
    await expect(oprf.evaluate({ accountId: "a", blindedElement: blinded, oprfKeyId: 1, purpose: "enroll" })).rejects.toBeInstanceOf(RateLimitedError);
    expect(oprf.attempts("a")).toBe(2);
    await oprf.evaluate({ accountId: "b", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
  });

  it("evaluates per account (info from the account charged), proves it, and keeps a rotated key working (D-53)", async () => {
    const oprf = new FakeOprfServer();
    const { blinded } = (await import("@noble/curves/ed25519.js")).ristretto255_oprf.oprf.blind(new Uint8Array(32));
    const forA = await oprf.evaluate({ accountId: "a", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
    const forB = await oprf.evaluate({ accountId: "b", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
    expect(Buffer.from(forA.evaluatedElement).equals(Buffer.from(forB.evaluatedElement))).toBe(false);
    expect(forA.proof).toHaveLength(64);
    expect(oprf.rotateKey()).toBe(2);
    const settings = await oprf.clientSettings();
    expect(settings.writeKeyId).toBe(2);
    expect(Object.keys(settings.keys)).toEqual(["1", "2"]);
    const again = await oprf.evaluate({ accountId: "a", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
    expect(Buffer.from(again.evaluatedElement).equals(Buffer.from(forA.evaluatedElement))).toBe(true);
  });
});

describe("member-keys (§11, D-43)", () => {
  it("only the account publishes its keys, at its newest version plus one", async () => {
    const server = new MemoryRecordStore();
    const create = (accountId: string, memberKeysVersion: number): WriteOp => {
      const key = { type: "member-keys", teamId: "t", accountId, memberKeysVersion } as RecordKey;
      return { op: "create", key, record: { ...key } as WireRecord };
    };
    await expect(server.as("mallory").commit([create("bob", 1)])).rejects.toThrow("member keys of another account");
    await expect(server.as("bob").commit([create("bob", 2)])).rejects.toBeInstanceOf(StoreConflictError);
    await server.as("bob").commit([create("bob", 1)]);
    await expect(server.as("bob").commit([create("bob", 3)])).rejects.toBeInstanceOf(StoreConflictError);
    await server.as("bob").commit([create("bob", 2)]);
  });
});

describe("archive of private records (rule 7, D-42)", () => {
  it("each team-state write archives the previous revision", async () => {
    const server = new MemoryRecordStore();
    const key = { type: "team-state", accountId: "a", teamId: "t" } as const;
    const record = (revision: number) => ({ ...key, revision }) as WireRecord;
    await server.as("a").commit([{ op: "compare-and-set", key, expectedRevision: null, record: record(1) }]);
    await server.as("a").commit([{ op: "compare-and-set", key, expectedRevision: 1, record: record(2) }]);
    expect(server.archived(key)).toEqual([record(1)]);
    server.restore(key);
    expect(await server.as("a").get(key)).toEqual(record(1));
  });

  it("restoreVersion makes an archived account key version current again, archiving later ones", async () => {
    const server = new MemoryRecordStore();
    const wrap = (accountKeyVersion: number) => ({ type: "account-key-wrap", accountId: "a", accountKeyVersion, method: "pin" }) as RecordKey;
    const create = (v: number): WriteOp => ({ op: "create", key: wrap(v), record: { ...wrap(v) } as WireRecord });
    await server.as("a").commit([create(1), { op: "set-account-key-version", accountId: "a", expected: null, accountKeyVersion: 1 }]);
    await server.as("a").commit([create(2), { op: "set-account-key-version", accountId: "a", expected: 1, accountKeyVersion: 2 }]);
    expect(await server.as("a").get(wrap(1))).toBeNull();

    server.restoreVersion("a", 1);
    expect(await server.as("a").getAccountKeyVersion("a")).toBe(1);
    expect(await server.as("a").get(wrap(1))).not.toBeNull();
    expect(await server.as("a").get(wrap(2))).toBeNull();
    expect(server.archived(wrap(2))).toHaveLength(1);
    expect(() => server.restoreVersion("a", 3)).toThrow();
  });
});
