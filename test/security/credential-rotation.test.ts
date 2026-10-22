/**
 * SP-09: A replaced PIN or recovery phrase stops working.
 * SP-25: An open vault alone can't change the account's credentials.
 * Threats: TH-10, TH-11, TH-36, TH-45.
 */
import { describe, expect, it } from "vitest";
import { hasValidRecoveryProof } from "../../src/records/member-keys.js";
import { replacePhrase, world } from "../support/fixtures.js";
import { bundleOf } from "../support/forge.js";
import { team } from "../support/teams.js";

const code = (c: string) => expect.objectContaining({ code: c });
const pinKey = { type: "account-key-wrap", accountId: "alice", accountKeyVersion: 1, method: "pin" } as const;

describe("SP-09: a replaced credential stops working", () => {
  it("the old PIN no longer opens the account after a change", async () => {
    const w = world();
    const alice = await w.account("alice");
    await alice.vault.changePin("9999", { currentPin: "1234" });
    const other = await w.device("alice");
    await expect(other.vault.unlockWithPin("1234")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await other.vault.unlockWithPin("9999");
  });

  it("the old phrase no longer opens the account after a replacement", async () => {
    const w = world();
    const alice = await w.account("alice");
    const { recoveryPhrase } = await replacePhrase(alice.vault, { currentPhrase: alice.recoveryPhrase });
    const other = await w.device("alice");
    await expect(other.vault.recover(alice.recoveryPhrase, "5555")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await other.vault.recover(recoveryPhrase, "5555");
  });

  it("Limit: a copy of the old wrap taken before the change still opens with the old PIN", async () => {
    const w = world();
    const alice = await w.account("alice");
    const oldWrap = await alice.store.get(pinKey);
    await alice.vault.changePin("9999", { currentPin: "1234" });
    const other = await w.device("alice");
    other.store.replace(pinKey, oldWrap);
    await other.vault.unlockWithPin("1234");
    expect(other.vault.isUnlocked).toBe(true);
  });

  it("TH-36: support undoes a session thief's PIN changes by restoring the archived wrap (D-39)", async () => {
    const w = world();
    const alice = await w.account("alice");
    // Someone holding the session and the PIN changes the PIN twice.
    await alice.vault.changePin("6666", { currentPin: "1234" });
    await alice.vault.changePin("7777", { currentPin: "6666" });
    const other = await w.device("alice");
    await expect(other.vault.unlockWithPin("1234")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    // Support picks the generation from before the theft.
    w.server.restore(pinKey, 0);
    await other.vault.unlockWithPin("1234");
    expect(other.vault.isUnlocked).toBe(true);
    expect(w.server.archived(pinKey)).toHaveLength(2);
  });

  it("a phrase confirmed with a typo is refused, and nothing is stored (D-35)", async () => {
    const w = world();
    const alice = await w.account("alice");
    const { recoveryPhrase } = alice.vault.beginRecoverySetup();
    const typo = recoveryPhrase.split(" ").reverse().join(" ");
    await expect(alice.vault.confirmRecoveryPhrase(typo)).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await (await w.device("alice")).vault.recover(alice.recoveryPhrase, "5555");
    // Spacing and case don't matter.
    await alice.vault.confirmRecoveryPhrase(`  ${recoveryPhrase.toUpperCase().replace(/ /g, "   ")} `, { currentPhrase: alice.recoveryPhrase });
    await (await w.device("alice")).vault.recover(recoveryPhrase, "5555");
  });

  it("a replacement re-keys every team; the re-keys are proven only with the current phrase (§5.6)", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const before = await bundleOf(bob.vault);

    const proven = await replacePhrase(bob.vault, { currentPhrase: bob.recoveryPhrase });
    expect(proven.report).toEqual({ rekeyed: ["team-1"], failed: [] });
    const first = await bundleOf(bob.vault);
    expect(first.memberKeysVersion).toBe(2);
    expect(hasValidRecoveryProof(first.published, before.published.recoveryPublicKey)).toBe(true);
    expect(await bob.vault.warnings()).toEqual([]);

    const unproven = await replacePhrase(bob.vault, { currentPin: bob.pin });
    expect(unproven.report).toEqual({ rekeyed: ["team-1"], failed: [] });
    const second = await bundleOf(bob.vault);
    expect(second.published.recoverySignature).toBeUndefined();
    expect(await bob.vault.warnings()).toEqual([]);

    // A current phrase that isn't the account's is refused before anything is stored.
    const { recoveryPhrase } = bob.vault.beginRecoverySetup();
    await expect(bob.vault.confirmRecoveryPhrase(recoveryPhrase, { currentPhrase: proven.recoveryPhrase })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    expect((await bundleOf(bob.vault)).memberKeysVersion).toBe(3);
  });
});

describe("SP-25: an open vault alone can't change the account's credentials", () => {
  it("refuses a PIN change, a phrase replacement and a rotation without a current credential, and writes nothing", async () => {
    const w = world();
    const { recoveryPhrase: other } = await w.account("mallory");
    const alice = await w.account("alice");
    const before = w.server.dump().length;
    await expect(alice.vault.changePin("6666", {} as never)).rejects.toEqual(code("MALFORMED_RECORD"));
    await expect(alice.vault.changePin("6666", { currentPin: "0000" })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await expect(alice.vault.changePin("6666", { phrase: other })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    const { recoveryPhrase } = alice.vault.beginRecoverySetup();
    await expect(alice.vault.confirmRecoveryPhrase(recoveryPhrase)).rejects.toEqual(code("MALFORMED_RECORD"));
    await expect(alice.vault.confirmRecoveryPhrase(recoveryPhrase, { currentPin: "0000" })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await expect(alice.vault.confirmRecoveryPhrase(recoveryPhrase, { currentPhrase: other })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await expect(alice.vault.rotate({ phrase: other })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    expect(w.server.dump().length).toBe(before);
    await (await w.device("alice")).vault.unlockWithPin("1234");
    await (await w.device("alice")).vault.recover(alice.recoveryPhrase, "1234");
  });

  it("each succeeds with a current credential; checking the PIN spends one evaluation", async () => {
    const w = world();
    const alice = await w.account("alice");
    let spent = w.oprf.attempts("alice");
    await alice.vault.changePin("6666", { currentPin: "1234" });
    expect(w.oprf.attempts("alice")).toBe(spent + 2); // the check, then the new wrap
    spent = w.oprf.attempts("alice");
    await alice.vault.changePin("7777", { phrase: alice.recoveryPhrase });
    expect(w.oprf.attempts("alice")).toBe(spent + 1);
    const { recoveryPhrase } = await replacePhrase(alice.vault, { currentPin: "7777" });
    await alice.vault.rotate({ phrase: recoveryPhrase });
    await (await w.device("alice")).vault.recover(recoveryPhrase, "1");
  });

  it("with no PIN set, a PIN change needs the phrase (D-40)", async () => {
    const w = world();
    const alice = await w.account("alice");
    await alice.vault.rotate({ phrase: alice.recoveryPhrase });
    await expect(alice.vault.changePin("2222", { currentPin: "1234" })).rejects.toEqual(code("PIN_NOT_SET_UP"));
    await alice.vault.changePin("2222", { phrase: alice.recoveryPhrase });
    await (await w.device("alice")).vault.unlockWithPin("2222");
  });

  it("TH-45: a stolen unlocked device can't take the remedy away", async () => {
    const { members, w } = await team("bob");
    const stolen = members.bob!;
    // The thief holds the open vault and no credential.
    const { recoveryPhrase } = stolen.vault.beginRecoverySetup();
    await expect(stolen.vault.confirmRecoveryPhrase(recoveryPhrase)).rejects.toEqual(code("MALFORMED_RECORD"));
    await expect(stolen.vault.changePin("6666", {} as never)).rejects.toEqual(code("MALFORMED_RECORD"));
    // The user secures the account from a clean device.
    const clean = await w.device("bob");
    await clean.vault.recover(stolen.recoveryPhrase, "2222");
    expect(await clean.vault.secureAccount({ phrase: stolen.recoveryPhrase })).toEqual({ rekeyed: ["team-1"], failed: [] });
    stolen.vault.lock();
    await expect(stolen.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
  });
});
