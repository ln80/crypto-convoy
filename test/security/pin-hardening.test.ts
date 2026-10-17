/**
 * SP-08: A PIN guess needs a server evaluation.
 * Threats: TH-07, TH-08, TH-34.
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

  it("an evaluation made for another account doesn't open the wrap", async () => {
    const w = world();
    await w.account("alice");
    const crossAccount: OprfService = {
      currentKeyId: () => w.oprf.currentKeyId(),
      evaluate: (request) => w.oprf.evaluate({ ...request, accountId: "mallory" }),
    };
    const device = await w.device("alice", { oprf: crossAccount });
    await expect(device.vault.unlockWithPin("1234")).rejects.toEqual(code("WRONG_CREDENTIAL"));
  });

  it("an evaluation with another server key doesn't open the wrap", async () => {
    const w = world();
    await w.account("alice");
    const device = await w.device("alice", { oprf: new FakeOprfServer() });
    await expect(device.vault.unlockWithPin("1234")).rejects.toEqual(code("WRONG_CREDENTIAL"));
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
      currentKeyId: () => w.oprf.currentKeyId(),
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

  it("upgrades an outdated PIN wrap on unlock, so a server key change needs no recovery", async () => {
    const w = world();
    await w.account("alice");
    w.oprf.rotateKey();
    const device = await w.device("alice");
    await device.vault.unlockWithPin("1234");
    const pin = await device.store.get({ type: "account-key-wrap", accountId: "alice", accountKeyVersion: 1, method: "pin" });
    expect((pin as { kdf: { oprfKeyId: number } }).kdf.oprfKeyId).toBe(2);
    await (await w.device("alice")).vault.unlockWithPin("1234");
  });
});
