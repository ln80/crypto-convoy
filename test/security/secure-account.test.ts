/**
 * SP-10, SP-11, SP-23: securing an account after a misused device (D-36).
 * Threats: TH-10, TH-12.
 */
import { describe, expect, it } from "vitest";
import { vaultInternals } from "../../src/account/vault.js";
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
    expect(report).toMatchObject({ rotatedTo: 2, approvedRekeys: ["bob"], needsHuman: [] });
    const access = (await accessOf(clean.store, "bob", 2))!;
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
});
