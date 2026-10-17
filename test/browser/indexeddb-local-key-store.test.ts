/**
 * Browser adapter storage (§3.7, D-08). SP-07: a stored anchor that can't be read is an error,
 * never read as absent. SP-10: the device key can't be copied off the device as a file.
 */
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { createIndexedDbLocalKeyStore } from "../../src/browser/index.js";
import { createVault } from "../../src/account/vault.js";
import { FakeOprfServer, MemoryRecordStore } from "../../src/testing/index.js";
import { FAST } from "../support/fixtures.js";

const fresh = () => new IDBFactory();
const rawRows = async (factory: IDBFactory, store: string) =>
  new Promise<unknown[]>((resolve) => {
    const open = factory.open("crypto-convoy", 1);
    open.onsuccess = () => {
      const req = open.result.transaction(store).objectStore(store).getAll();
      req.onsuccess = () => resolve(req.result);
    };
  });

describe("IndexedDB LocalKeyStore", () => {
  it("round-trips devices, versions and anchors, and survives reopening", async () => {
    const factory = fresh();
    const store = await createIndexedDbLocalKeyStore({ indexedDB: factory });
    const deviceKey = new Uint8Array(32).fill(7);
    await store.setDevice("alice", { deviceId: "dev-1", deviceKey: deviceKey.slice() });
    await store.setAccountKeyVersion("alice", 3);
    await store.setAnchor("alice", "team-1", { version: 4, hash: new Uint8Array(32).fill(9) });

    const again = await createIndexedDbLocalKeyStore({ indexedDB: factory });
    expect(await again.getDevice("alice")).toEqual({ deviceId: "dev-1", deviceKey });
    expect(await again.getAccountKeyVersion("alice")).toBe(3);
    expect((await again.getAnchor("alice", "team-1"))?.version).toBe(4);
    expect(await again.getAnchor("alice", "team-2")).toBeNull();
    expect(await again.getDevice("bob")).toBeNull();
  });

  it("stores no raw device key, and its wrapping key is not extractable", async () => {
    const factory = fresh();
    const store = await createIndexedDbLocalKeyStore({ indexedDB: factory });
    const deviceKey = crypto.getRandomValues(new Uint8Array(32));
    await store.setDevice("alice", { deviceId: "dev-1", deviceKey: deviceKey.slice() });
    for (const row of await rawRows(factory, "values")) {
      expect(Buffer.from(row as Uint8Array).includes(Buffer.from(deviceKey))).toBe(false);
    }
    const [wrappingKey] = (await rawRows(factory, "keys")) as CryptoKey[];
    expect(wrappingKey!.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", wrappingKey!)).rejects.toThrow();
  });

  it("refuses a tampered value, or one moved to another account or team, instead of reading it as absent", async () => {
    const factory = fresh();
    const store = await createIndexedDbLocalKeyStore({ indexedDB: factory });
    await store.setAnchor("alice", "team-1", { version: 2, hash: new Uint8Array(32) });
    const [row] = (await rawRows(factory, "values")) as Uint8Array[];
    const write = (key: string, value: Uint8Array) =>
      new Promise<void>((resolve) => {
        const open = factory.open("crypto-convoy", 1);
        open.onsuccess = () => {
          const tx = open.result.transaction("values", "readwrite");
          tx.objectStore("values").put(value, key);
          tx.oncomplete = () => resolve();
        };
      });
    await write("anchor\0alice\0team-2", row!);
    await expect(store.getAnchor("alice", "team-2")).rejects.toEqual(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
    const flipped = row!.slice();
    flipped[flipped.length - 1]! ^= 1;
    await write("anchor\0alice\0team-1", flipped);
    await expect(store.getAnchor("alice", "team-1")).rejects.toEqual(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
  });

  it("clear removes one account's values only", async () => {
    const store = await createIndexedDbLocalKeyStore({ indexedDB: fresh() });
    await store.setAccountKeyVersion("alice", 1);
    await store.setAccountKeyVersion("bob", 1);
    await store.setAnchor("alice", "team-1", { version: 1, hash: new Uint8Array(32) });
    await store.clear("alice");
    expect(await store.getAccountKeyVersion("alice")).toBeNull();
    expect(await store.getAnchor("alice", "team-1")).toBeNull();
    expect(await store.getAccountKeyVersion("bob")).toBe(1);
  });

  it("works as the vault's LocalKeyStore", async () => {
    const server = new MemoryRecordStore();
    const oprf = new FakeOprfServer();
    const localKeys = await createIndexedDbLocalKeyStore({ indexedDB: fresh() });
    const vault = await createVault({ store: server.as("alice"), oprf, localKeys, settings: FAST }, "alice");
    await vault.setup("1234");
    await (await vault.createTeam("team-1")).createItem("i", [{ content: new Uint8Array([1]) }]);
    vault.lock();
    await vault.unlock();
    expect((await vault.openTeam("team-1")).state).toBe("ready");
  });
});
