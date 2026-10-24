/**
 * SP-19: Recovering an account requires authorized material.
 * Threats: TH-11, TH-18, TH-05.
 */
import { describe, expect, it } from "vitest";
import { accountKeyWrapToJson, createAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { replacePhrase, world } from "../support/fixtures.js";

const code = (c: string) => expect.objectContaining({ code: c });

describe("SP-19: only authorized material opens the account key", () => {
  it("each authorized path succeeds: device, PIN with evaluation, phrase", async () => {
    const w = world();
    const laptop = await w.account("alice");
    laptop.vault.lock();
    await laptop.vault.unlock();
    await (await w.device("alice")).vault.unlockWithPin("1234");
    await (await w.device("alice")).vault.recover(laptop.recoveryPhrase, "4321");
  });

  it("the phrase works when the PIN budget is spent; only the new PIN waits", async () => {
    const w = world({ budget: 2 });
    const laptop = await w.account("alice"); // spends both: setup and the recovery setup's PIN check (D-61)
    const phone = await w.device("alice");
    await expect(phone.vault.recover(laptop.recoveryPhrase, "4321")).rejects.toEqual(code("PIN_RATE_LIMITED"));
    expect(phone.vault.isUnlocked).toBe(true);
    phone.vault.lock();
    await phone.vault.unlock();
  });

  it("the server can't make a client accept an account key it forged", async () => {
    const w = world();
    const alice = await w.account("alice");
    const forged = (method: "pin" | "recovery") =>
      accountKeyWrapToJson(
        createAccountKeyWrap(
          cc1,
          {
            accountId: "alice",
            accountKeyVersion: 1,
            method,
            ...(method === "pin" ? { kdf: { salt: cc1.randomBytes(16), opslimit: 2, memlimit: 64 * 1024 * 1024, oprfKeyId: 1 } } : {}),
          },
          cc1.randomBytes(32),
          cc1.randomBytes(32),
          method === "recovery" ? cc1.signingKeyPair(cc1.randomBytes(32)).publicKey : undefined,
        ),
      );

    const byPin = await w.device("alice");
    byPin.store.replace({ type: "account-key-wrap", method: "pin" }, forged("pin"));
    await expect(byPin.vault.unlockWithPin(alice.pin)).rejects.toEqual(code("WRONG_CREDENTIAL"));

    const byPhrase = await w.device("alice");
    byPhrase.store.replace({ type: "account-key-wrap", method: "recovery" }, forged("recovery"));
    await expect(byPhrase.vault.recover(alice.recoveryPhrase, "1")).rejects.toEqual(code("WRONG_CREDENTIAL"));
  });

  it("a revoked device and an old phrase fail", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const [entry] = await laptop.vault.listDevices();
    await laptop.vault.revokeDevice(entry!.deviceId);
    await replacePhrase(laptop.vault, { currentPhrase: laptop.recoveryPhrase });
    laptop.vault.lock();
    await expect(laptop.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    await expect((await w.device("alice")).vault.recover(laptop.recoveryPhrase, "1")).rejects.toEqual(code("WRONG_CREDENTIAL"));
  });

  it("a device with stored state refuses an older account key version", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const phone = await w.device("alice");
    await phone.vault.unlockWithPin("1234");
    await laptop.vault.rotate({ phrase: laptop.recoveryPhrase, newPin: "1234" });
    await phone.vault.unlockWithPin("1234");
    phone.store.accountVersion(1);
    phone.vault.lock();
    await expect(phone.vault.unlockWithPin("1234")).rejects.toEqual(expect.objectContaining({ code: "TRUST_FAILURE", reason: "rollback" }));
  });

  it("Limit: a device with no stored state adopts a retired version the server kept", async () => {
    const w = world();
    const laptop = await w.account("alice");
    await laptop.vault.rotate({ phrase: laptop.recoveryPhrase, newPin: "1234" });
    // The retired version made current again (a server that kept it, or a support restore, TH-48); an honest
    // server refuses wraps at a retired version, so the device registers only where the server serves that one (D-58).
    w.server.restoreVersion("alice", 1);
    const fresh = await w.device("alice", { localKeys: new MemoryLocalKeyStore() });
    await fresh.vault.unlockWithPin("1234");
    expect(fresh.vault.isUnlocked).toBe(true);
  });
});
