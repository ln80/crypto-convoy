/**
 * SP-08: A PIN guess needs a server evaluation.
 * Threats: TH-07, TH-08, TH-34, TH-51.
 */
import { describe, expect, it } from "vitest";
import { string, bytes } from "../../src/encoding/canonical.js";
import { labelled } from "../../src/encoding/labels.js";
import type { OprfService } from "../../src/ports.js";
import { openAccountKeyWrap, parseAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { FakeOprfServer } from "../../src/testing/index.js";
import { FAST, world } from "../support/fixtures.js";

const code = (c: string) => expect.objectContaining({ code: c });
const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });
const pinWrapOf = async (store: { get: (k: never) => Promise<unknown> }) =>
  (await store.get({ type: "account-key-wrap", accountId: "alice", accountKeyVersion: 1, method: "pin" } as never)) as { kdf: { oprfKeyId: number } } | null;

describe("SP-08: a PIN guess needs a server evaluation", () => {
  it("a stolen PIN wrap doesn't open with the right PIN and no evaluation", async () => {
    const w = world();
    await w.account("alice");
    const stolen = w.server.dump().find((r) => r["method"] === "pin")!;
    const wrap = parseAccountKeyWrap(stolen, { accountId: "alice", accountKeyVersion: 1, method: "pin" });
    const kdf = wrap.kdf!;
    const a = cc1.passwordHash(new TextEncoder().encode("1234"), kdf.salt, kdf.opslimit, kdf.memlimit);
    for (const y of [new Uint8Array(64), cc1.hash(a)]) {
      const guess = cc1.keyedHash(a, labelled("pin-key", string("alice"), bytes(y)));
      expect(() => openAccountKeyWrap(wrap, guess)).toThrow(code("WRONG_CREDENTIAL"));
    }
    expect(() => openAccountKeyWrap(wrap, a)).toThrow(code("WRONG_CREDENTIAL"));
  });

  it("an evaluation made for another account is refused: its proof is for another account (D-53)", async () => {
    const w = world();
    await w.account("alice");
    const crossAccount: OprfService = { evaluate: (request) => w.oprf.evaluate({ ...request, accountId: "mallory" }) };
    const device = await w.device("alice", { oprf: crossAccount });
    await expect(device.vault.unlockWithPin("1234")).rejects.toEqual(trust("bad_signature"));
  });

  it("an evaluation with another server key is refused before anything is derived (TH-51)", async () => {
    const w = world();
    await w.account("alice");
    const device = await w.device("alice", { oprf: new FakeOprfServer() });
    await expect(device.vault.unlockWithPin("1234")).rejects.toEqual(trust("bad_signature"));
  });

  it("every evaluation counts, wrong PINs included, until the budget refuses", async () => {
    const w = world({ budget: 4 });
    await w.account("alice"); // setup: 1 evaluation
    const device = await w.device("alice");
    await expect(device.vault.unlockWithPin("0000")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await expect(device.vault.unlockWithPin("1111")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await device.vault.unlockWithPin("1234");
    expect(w.oprf.attempts("alice")).toBe(4);
    await expect((await w.device("alice")).vault.unlockWithPin("1234")).rejects.toEqual(code("PIN_RATE_LIMITED"));
  });

  it("never retries an evaluation automatically", async () => {
    const w = world();
    await w.account("alice");
    let calls = 0;
    const flaky: OprfService = {
      evaluate: async () => {
        calls += 1;
        throw new Error("network");
      },
    };
    const device = await w.device("alice", { oprf: flaky });
    await expect(device.vault.unlockWithPin("1234")).rejects.toEqual(code("STORE_ERROR"));
    expect(calls).toBe(1);
  });

  it("refuses a PIN wrap below the reader's minimum cost before any evaluation (TH-34)", async () => {
    const w = world();
    await w.account("alice");
    const before = w.oprf.attempts("alice");
    const strict = { argon2: { write: { opslimit: 3, memlimit: 64 * 1024 * 1024 }, min: { opslimit: 3, memlimit: 64 * 1024 * 1024 } } };
    const device = await w.device("alice", { settings: strict });
    await expect(device.vault.unlockWithPin("1234")).rejects.toEqual(code("MALFORMED_RECORD"));
    expect(w.oprf.attempts("alice")).toBe(before);
  });

  it("refuses settings below the library's hard floor (D-17)", async () => {
    const w = world();
    const weak = { argon2: { write: { opslimit: 1, memlimit: 8 * 1024 * 1024 } } };
    await expect(w.device("alice", { settings: weak })).rejects.toEqual(code("MALFORMED_RECORD"));
    expect(FAST.argon2?.min?.opslimit).toBe(2);
  });

  it("upgrades a PIN wrap to the settings' writeKeyId on unlock, so a key change needs no recovery (D-53)", async () => {
    const w = world();
    await w.account("alice");
    w.oprf.rotateKey();
    // A release that pins key 2 and writes with it.
    const device = await w.device("alice");
    await device.vault.unlockWithPin("1234");
    const pin = await device.store.get({ type: "account-key-wrap", accountId: "alice", accountKeyVersion: 1, method: "pin" });
    expect((pin as { kdf: { oprfKeyId: number } }).kdf.oprfKeyId).toBe(2);
    await (await w.device("alice")).vault.unlockWithPin("1234");
  });

  it("TH-51: a front end that answers enrolments with a key of its own makes no wrap", async () => {
    const w = world();
    const forger = new FakeOprfServer(); // a key the front end chose, not the pinned one
    const device = await w.device("alice", { oprf: forger });
    await expect(device.vault.setup("1234")).rejects.toEqual(trust("bad_signature"));
    expect(await device.store.getAccountKeyVersion("alice")).toBeNull();
  });

  it("TH-51: a proof replayed from an earlier evaluation is refused", async () => {
    const w = world();
    await w.account("alice");
    let recorded: Awaited<ReturnType<OprfService["evaluate"]>> | undefined;
    const recorder: OprfService = { evaluate: async (r) => (recorded = await w.oprf.evaluate(r)) };
    await (await w.device("alice", { oprf: recorder })).vault.unlockWithPin("1234");
    const replay: OprfService = { evaluate: async () => recorded! };
    await expect((await w.device("alice", { oprf: replay })).vault.unlockWithPin("1234")).rejects.toEqual(trust("bad_signature"));
  });

  it("a key id with no pinned public key is UNSUPPORTED_VERSION before any evaluation", async () => {
    const w = world();
    await w.account("alice");
    w.oprf.rotateKey();
    const { keys } = await w.oprf.clientSettings();
    const before = w.oprf.attempts("alice");
    const device = await w.device("alice", { settings: { ...FAST, oprf: { keys: { 2: keys[2]! }, writeKeyId: 2 } } });
    await expect(device.vault.unlockWithPin("1234")).rejects.toEqual(code("UNSUPPORTED_VERSION"));
    expect(w.oprf.attempts("alice")).toBe(before);
  });

  it("the server never chooses the key id: writers use the settings' writeKeyId (D-53)", async () => {
    const w = world();
    await w.account("alice");
    w.oprf.rotateKey();
    // A release that pins key 2 for reading but still writes with key 1 (the first of two releases).
    const device = await w.device("alice", { settings: { ...FAST, oprf: await w.oprf.clientSettings(1) } });
    await device.vault.unlockWithPin("1234");
    expect((await pinWrapOf(device.store))!.kdf.oprfKeyId).toBe(1);
    await device.vault.changePin("5678", { currentPin: "1234" });
    expect((await pinWrapOf(device.store))!.kdf.oprfKeyId).toBe(1);
  });

  it("the unlock stands when only its upgrade fails; the old wrap is kept (§5.4)", async () => {
    const w = world();
    await w.account("alice");
    w.oprf.rotateKey();
    const refuseKey2: OprfService = {
      evaluate: async (r) => {
        if (r.oprfKeyId === 2) throw new Error("key service down");
        return w.oprf.evaluate(r);
      },
    };
    const device = await w.device("alice", { oprf: refuseKey2 });
    await device.vault.unlockWithPin("1234");
    expect((await device.vault.status()).account).toBe("unlocked");
    expect((await pinWrapOf(device.store))!.kdf.oprfKeyId).toBe(1);
  });

  it("refuses OPRF settings with an invalid public key or a writeKeyId with no key", async () => {
    const w = world();
    await expect(w.device("alice", { settings: { ...FAST, oprf: { keys: { 1: new Uint8Array(32) }, writeKeyId: 1 } } })).rejects.toEqual(code("MALFORMED_RECORD"));
    const { keys } = await w.oprf.clientSettings();
    await expect(w.device("alice", { settings: { ...FAST, oprf: { keys, writeKeyId: 7 } } })).rejects.toEqual(code("MALFORMED_RECORD"));
  });
});

