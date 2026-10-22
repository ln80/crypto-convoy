/**
 * SP-26: A session can't destroy an account's private records.
 * Threats: TH-11, TH-36, TH-46.
 */
import { describe, expect, it } from "vitest";
import { replacePhrase } from "../support/fixtures.js";
import { team } from "../support/teams.js";

const code = (c: string) => expect.objectContaining({ code: c });
const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });
const stateKey = { type: "team-state", accountId: "bob", teamId: "team-1" } as const;
const b64 = (n: number) => Buffer.alloc(n, 7).toString("base64url");

describe("SP-26: a session can't destroy an account's private records", () => {
  it("TH-46: a garbage team-state stops the team; restoring the previous revision reopens it (D-42)", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    const state = (await bob.store.get(stateKey)) as { revision: number };
    // Someone holding bob's session writes a well-formed team-state holding garbage.
    await bob.store.commit([
      { op: "compare-and-set", key: stateKey, expectedRevision: state.revision, record: { ...state, revision: state.revision + 1, wrappedState: { nonce: b64(24), ciphertext: b64(56) } } },
    ]);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("state_unreadable"));
    expect(w.server.archived(stateKey)).toHaveLength(state.revision);

    w.server.restore(stateKey);
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("TH-46: a deleted member keys wrap is restored", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    const wrapKey = { type: "member-keys-wrap", accountId: "bob", teamId: "team-1", memberKeysVersion: 1, accountKeyVersion: 1 } as const;
    await bob.store.commit([{ op: "delete", key: wrapKey }]);
    expect((await bob.vault.openTeam("team-1")).state).toBe("not-joined");

    w.server.restore(wrapKey);
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("TH-11: a PIN thief replaces the phrase and rotates; restoring the version from before brings the account back (D-42)", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    // The thief holds bob's session and PIN, on their own device.
    const thief = await w.device("bob");
    await thief.vault.unlockWithPin(bob.pin);
    const { recoveryPhrase: thiefPhrase } = await replacePhrase(thief.vault, { currentPin: bob.pin });
    await thief.vault.rotate({ phrase: thiefPhrase, newPin: "6666" });

    // Bob is locked out: his device, PIN and phrase open nothing.
    bob.vault.lock();
    await expect(bob.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    await expect((await w.device("bob")).vault.unlockWithPin(bob.pin)).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await expect((await w.device("bob")).vault.recover(bob.recoveryPhrase, "1")).rejects.toEqual(code("WRONG_CREDENTIAL"));

    // Support restores version 1, and the recovery wrap generation from before the takeover.
    w.server.restoreVersion("bob", 1);
    w.server.restore({ type: "account-key-wrap", accountId: "bob", accountKeyVersion: 1, method: "recovery" }, 0);

    // The thief's device accepted version 2: it refuses the restored one.
    thief.vault.lock();
    await expect(thief.vault.unlock()).rejects.toEqual(trust("rollback"));

    // Bob's device, PIN and phrase work again; he secures the account, and his team follows.
    await bob.vault.unlock();
    await (await w.device("bob")).vault.unlockWithPin(bob.pin);
    expect(await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "2222" })).toEqual({ rekeyed: ["team-1"], failed: [] });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });
});
