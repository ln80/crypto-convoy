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
    case "grant": return pick("teamId", "accountId", "memberKeysVersion", "teamKeyVersion") as RecordKey;
    case "item": return pick("teamId", "itemId") as RecordKey;
    case "inbox": return pick("teamId", "inboxId") as RecordKey;
    case "member-keys": return pick("teamId", "accountId", "memberKeysVersion") as RecordKey;
    case "account-key-wrap": return pick("accountId", "accountKeyVersion", "method") as RecordKey;
    default: throw new Error(type);
  }
};
const create = (record: WireRecord): WriteOp => ({ op: "create", key: keyOf(record), record });
const conflict = expect.any(StoreConflictError);

function teamStore() {
  const server = new MemoryRecordStore();
  return { server, alice: server.as("alice") };
}

describe("server contract (§11)", () => {
  it("creates a team only with its version 1 and the creator's grant, atomically", async () => {
    const { alice } = teamStore();
    await expect(alice.commit([create(r["team-key-version"])])).rejects.toEqual(conflict);
    expect(await alice.list({ type: "team-key-version", teamId: "team-1", fromVersion: 1 })).toEqual([]);
    await alice.commit([create(r["team-key-version"]), create(r.grant)]);
    expect(await alice.list({ type: "team-key-version", teamId: "team-1", fromVersion: 1 })).toHaveLength(1);
  });

  it("never overwrites a write-once record", async () => {
    const { alice } = teamStore();
    await alice.commit([create(r["member-keys"])]);
    await expect(alice.commit([create(r["member-keys"])])).rejects.toEqual(conflict);
  });

  it("accepts a new version only as current + 1", async () => {
    const { alice } = teamStore();
    const v3 = { ...r["team-key-version"], version: 3 };
    await expect(alice.commit([create(v3), create({ ...r.grant, teamKeyVersion: 3 })])).rejects.toEqual(conflict);
  });

  it("accepts grants, items and inboxes only at the current version", async () => {
    const { alice } = teamStore();
    await alice.commit([create(r["team-key-version"]), create(r.grant)]);
    await alice.commit([create(r.item), create(r.inbox)]);
    await expect(alice.commit([create({ ...r.item, itemId: "item-2", teamKeyVersion: 2 })])).rejects.toEqual(conflict);
    await expect(alice.commit([create({ ...r.grant, accountId: "bob", teamKeyVersion: 2 })])).rejects.toEqual(conflict);
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

  it("soft-deletes: a deleted record is no longer served, and can be restored (TH-36)", async () => {
    const { server, alice } = teamStore();
    const wrap = r["account-key-wrap"];
    await alice.commit([create(wrap)]);
    await alice.commit([{ op: "delete", key: keyOf(wrap) }]);
    expect(await alice.get(keyOf(wrap))).toBeNull();
    expect(server.dump()).toContainEqual(wrap);
    await alice.commit([{ op: "delete", key: keyOf(wrap) }, create(wrap)]);
    expect(await alice.get(keyOf(wrap))).toEqual(wrap);
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

  it("uses a different key per account and keeps a rotated key working", async () => {
    const oprf = new FakeOprfServer();
    const { oprf: client } = (await import("@noble/curves/ed25519.js")).ristretto255_oprf;
    const { blinded } = client.blind(new Uint8Array(32));
    const forA = await oprf.evaluate({ accountId: "a", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
    const forB = await oprf.evaluate({ accountId: "b", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
    expect(Buffer.from(forA).equals(Buffer.from(forB))).toBe(false);
    expect(oprf.rotateKey()).toBe(2);
    expect(await oprf.currentKeyId()).toBe(2);
    const again = await oprf.evaluate({ accountId: "a", blindedElement: blinded, oprfKeyId: 1, purpose: "unlock" });
    expect(Buffer.from(again).equals(Buffer.from(forA))).toBe(true);
  });
});
