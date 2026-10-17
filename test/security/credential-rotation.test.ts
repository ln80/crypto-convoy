/**
 * SP-09: A replaced PIN or recovery phrase stops working.
 * Threats: TH-11.
 */
import { describe, expect, it } from "vitest";
import { world } from "../support/fixtures.js";

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
    const { recoveryPhrase } = await alice.vault.replaceRecoveryPhrase();
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
});
