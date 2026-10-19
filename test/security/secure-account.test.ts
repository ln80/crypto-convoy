/**
 * SP-10, SP-11, SP-23: securing an account after a misused device (D-36), also with the
 * PIN budget spent (D-40).
 * Threats: TH-10, TH-12, TH-44.
 */
import { describe, expect, it } from "vitest";
import { vaultInternals } from "../../src/account/vault.js";
import { world } from "../support/fixtures.js";
import { accessOf, bundleOf } from "../support/forge.js";
import { team } from "../support/teams.js";

const code = (c: string) => expect.objectContaining({ code: c });

describe("SP-10 / SP-11 / SP-23: secureAccount", () => {
  it("after secureAccount and an owner's reconcile, keys copied from the device open nothing new", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    const copied = { bundle: await bundleOf(bob.vault), accountKey: vaultInternals(bob.vault).account().key.slice() };

    // From a device the thief never touched.
    const clean = await w.device("bob");
    await clean.vault.recover(bob.recoveryPhrase, "1111");
    expect(await clean.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "2222" })).toEqual({ rekeyed: ["team-1"], failed: [] });

    // Every other device is cut, and the old PIN is gone.
    bob.vault.lock();
    await expect(bob.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    await expect((await w.device("bob")).vault.unlockWithPin("1111")).rejects.toEqual(code("WRONG_CREDENTIAL"));

    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toMatchObject({ rotatedTo: 3, approvedRekeys: ["bob"], needsHuman: [] });
    const access = (await accessOf(clean.store, "bob", 3))!;
    expect(() => access.open(copied.bundle.pairs.encryption)).toThrow(code("DECRYPTION_FAILED"));
    expect((await clean.vault.openTeam("team-1")).state).toBe("ready");
    expect(Buffer.from(vaultInternals(clean.vault).account().key).equals(Buffer.from(copied.accountKey))).toBe(false);
  });

  it("reports a team that failed to re-key; a retry with the phrase completes it", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    await bob.vault.createTeam("team-2");
    let failOnce = true;
    bob.store.onCommit((ops) => {
      if (failOnce && ops.some((op) => op.op === "create" && op.key.type === "member-keys" && op.key.teamId === "team-2")) {
        failOnce = false;
        throw new Error("network");
      }
    });
    const report = await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "2222" });
    expect(report).toEqual({ rekeyed: ["team-1"], failed: ["team-2"] });
    await bob.vault.rekey("team-2", { phrase: bob.recoveryPhrase });
    expect((await bundleOf(bob.vault, "team-2")).published.recoverySignature).toBeDefined();
  });

  it("refuses a phrase that isn't the account's before changing anything", async () => {
    const { members, w } = await team("bob");
    const { recoveryPhrase: other } = await w.account("mallory");
    await expect(members.bob!.vault.secureAccount({ phrase: other, newPin: "2222" })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    expect(await members.bob!.store.getAccountKeyVersion("bob")).toBe(1);
  });

  it("TH-44: with the PIN budget spent, the phrase alone cuts the thief's PIN and devices (D-40)", async () => {
    const w = world({ budget: 4 });
    const alice = await w.account("alice"); // 1 evaluation
    // A session thief sets their own PIN, then spends the rest of the budget.
    await alice.vault.changePin("6666"); // 2
    const guesses = await w.device("alice");
    await expect(guesses.vault.unlockWithPin("0000")).rejects.toEqual(code("WRONG_CREDENTIAL")); // 3
    await expect(guesses.vault.unlockWithPin("0001")).rejects.toEqual(code("WRONG_CREDENTIAL")); // 4
    await expect(guesses.vault.unlockWithPin("0002")).rejects.toEqual(code("PIN_RATE_LIMITED"));

    // The user recovers on a clean device: unlocked and registered, but the PIN can't change.
    const clean = await w.device("alice");
    await expect(clean.vault.recover(alice.recoveryPhrase, "1111")).rejects.toEqual(code("PIN_RATE_LIMITED"));
    expect(clean.vault.isUnlocked).toBe(true);
    await expect(clean.vault.secureAccount({ phrase: alice.recoveryPhrase, newPin: "1111" })).rejects.toEqual(code("PIN_RATE_LIMITED"));
    expect(await clean.store.getAccountKeyVersion("alice")).toBe(1); // nothing written

    // The phrase alone: the thief's PIN and devices stop working, with no evaluation spent.
    await clean.vault.secureAccount({ phrase: alice.recoveryPhrase });
    expect(await clean.vault.status()).toMatchObject({ account: "unlocked", pin: "not-set-up", recovery: "set-up" });
    expect(await clean.vault.warnings()).toContainEqual({ code: "pin-not-set-up", teamIds: [], action: "changePin" });
    alice.vault.lock();
    await expect(alice.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    const before = w.oprf.attempts("alice");
    await expect((await w.device("alice")).vault.unlockWithPin("6666")).rejects.toEqual(code("PIN_NOT_SET_UP"));
    expect(w.oprf.attempts("alice")).toBe(before);

    // Once the budget allows, the user sets a PIN: it is created, not replaced.
    w.oprf.resetBudget("alice");
    await clean.vault.changePin("2222");
    expect((await clean.vault.status()).pin).toBe("set-up");
    await (await w.device("alice")).vault.unlockWithPin("2222");
  });

  it("refuses a rotation with neither a PIN nor the phrase", async () => {
    const w = world();
    const alice = await w.account("alice");
    await expect(alice.vault.rotate({})).rejects.toEqual(code("MALFORMED_RECORD"));
    expect(await alice.store.getAccountKeyVersion("alice")).toBe(1);
  });
});
