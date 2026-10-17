/**
 * SP-09: A replaced PIN or recovery phrase stops working.
 * Threats: TH-11.
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
    await alice.vault.changePin("9999");
    const other = await w.device("alice");
    await expect(other.vault.unlockWithPin("1234")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await other.vault.unlockWithPin("9999");
  });

  it("the old phrase no longer opens the account after a replacement", async () => {
    const w = world();
    const alice = await w.account("alice");
    const { recoveryPhrase } = await replacePhrase(alice.vault);
    const other = await w.device("alice");
    await expect(other.vault.recover(alice.recoveryPhrase, "5555")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await other.vault.recover(recoveryPhrase, "5555");
  });

  it("Limit: a copy of the old wrap taken before the change still opens with the old PIN", async () => {
    const w = world();
    const alice = await w.account("alice");
    const oldWrap = await alice.store.get(pinKey);
    await alice.vault.changePin("9999");
    const other = await w.device("alice");
    other.store.replace(pinKey, oldWrap);
    await other.vault.unlockWithPin("1234");
    expect(other.vault.isUnlocked).toBe(true);
  });

  it("a phrase confirmed with a typo is refused, and nothing is stored (D-35)", async () => {
    const w = world();
    const alice = await w.account("alice");
    const { recoveryPhrase } = alice.vault.beginRecoverySetup();
    const typo = recoveryPhrase.split(" ").reverse().join(" ");
    await expect(alice.vault.confirmRecoveryPhrase(typo)).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await (await w.device("alice")).vault.recover(alice.recoveryPhrase, "5555");
    // Spacing and case don't matter.
    await alice.vault.confirmRecoveryPhrase(`  ${recoveryPhrase.toUpperCase().replace(/ /g, "   ")} `);
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

    const unproven = await replacePhrase(bob.vault);
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
