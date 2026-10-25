/**
 * SP-26: A session can't destroy an account's private records.
 * Threats: TH-10, TH-11, TH-36, TH-45, TH-46, TH-48.
 */
import { describe, expect, it } from "vitest";
import { replacePhrase } from "../support/fixtures.js";
import { team } from "../support/teams.js";
import { forgeMemberKeys, strangerKeys, bundleOf } from "../support/forge.js";
import { vaultInternals } from "../../src/account/vault.js";
import { createMemberKeysWrap, memberKeysWrapToJson } from "../../src/records/member-keys-wrap.js";
import { cc1 } from "../../src/suites/cc1/index.js";

const code = (c: string) => expect.objectContaining({ code: c });
const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });
const stateKey = { type: "team-state", accountId: "bob", teamId: "team-1" } as const;
const b64 = (n: number) => Buffer.alloc(n, 7).toString("base64url");

describe("SP-26: a session can't destroy an account's private records", () => {
  it("TH-46: a garbage team-state is absent where the keys hold a floor; the next open replaces it (D-62)", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    const state = (await bob.store.get(stateKey)) as { revision: number };
    // Someone holding bob's session writes a well-formed team-state holding garbage.
    await bob.store.commit([
      { op: "compare-and-set", key: stateKey, expectedRevision: state.revision, record: { ...state, revision: state.revision + 1, wrappedState: { nonce: b64(24), ciphertext: b64(56) } } },
    ]);
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
    // Replaced under bob's current keys, the garbage revision archived (D-42).
    const replaced = (await bob.store.get(stateKey)) as { revision: number };
    expect(replaced.revision).toBe(state.revision + 2);
    expect(w.server.archived(stateKey)).toHaveLength(state.revision + 1);
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("TH-46: a malformed team-state is absent where the keys hold a floor, and replaced; one at an unknown version is left alone (D-62)", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    const write = async (record: (state: Record<string, unknown>) => Record<string, unknown>) => {
      const state = (await bob.store.get(stateKey)) as Record<string, unknown> & { revision: number };
      await bob.store.commit([{ op: "compare-and-set", key: stateKey, expectedRevision: state.revision, record: { ...record(state), revision: state.revision + 1 } }]);
      return state.revision + 1;
    };
    // A ciphertext too short for its suite: a known version that fails its shape is absent and replaced.
    const short = await write((state) => ({ ...state, wrappedState: { nonce: b64(3), ciphertext: b64(3) } }));
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
    expect(((await bob.store.get(stateKey)) as { revision: number }).revision).toBe(short + 1);
    // A version this library doesn't read: absent, never replaced, since readers ship first (§10).
    const newer = await write((state) => ({ ...state, v: 2 }));
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
    expect(await bob.store.get(stateKey)).toMatchObject({ v: 2, revision: newer });
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

  it("TH-45: a deleted recovery wrap opens no setup without a credential (D-61); a restore brings the phrase back", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    // A thief with bob's stolen device: an open vault and the session, no credential.
    const stolen = bob.vault;
    await bob.store.commit([{ op: "delete", key: { type: "account-key-wrap", accountId: "bob", accountKeyVersion: 1, method: "recovery" } }]);
    const { recoveryPhrase: thiefPhrase } = stolen.beginRecoverySetup();
    await expect(stolen.confirmRecoveryPhrase(thiefPhrase)).rejects.toEqual(code("MALFORMED_RECORD"));
    await expect(stolen.confirmRecoveryPhrase(thiefPhrase, { currentPin: "0000" })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    await expect(stolen.rotate({ phrase: thiefPhrase })).rejects.toEqual(code("RECOVERY_NOT_SET_UP"));

    // Bob sees recovery missing; the phrase can't open anything until support restores the wrap.
    await expect((await w.device("bob")).vault.recover(bob.recoveryPhrase, "1")).rejects.toEqual(code("RECOVERY_NOT_SET_UP"));
    w.server.restore({ type: "account-key-wrap", accountId: "bob", accountKeyVersion: 1, method: "recovery" });
    const phone = await w.device("bob");
    await phone.vault.recover(bob.recoveryPhrase, "2222");
    expect((await phone.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "3333" })).failed).toEqual([]);
  });

  it("TH-11: a phrase thief's takeover is restored; securing with a new phrase leaves the leaked one opening nothing (D-45)", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    const thief = await w.device("bob");
    await thief.vault.recover(bob.recoveryPhrase, "6666");
    const { recoveryPhrase: thiefPhrase } = await replacePhrase(thief.vault, { currentPhrase: bob.recoveryPhrase });
    await thief.vault.rotate({ phrase: thiefPhrase, newPin: "6666" });
    // The thief's re-keys were proven by bob's phrase: the owner's routine reconcile approves them.
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });

    w.server.restoreVersion("bob", 1);
    w.server.restore({ type: "account-key-wrap", accountId: "bob", accountKeyVersion: 1, method: "recovery" }, 0);
    await bob.vault.unlock();
    const { recoveryPhrase: newPhrase } = bob.vault.beginRecoverySetup();
    await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPhrase, newPin: "2222" });

    // The restored phrase was the thief's way in: it no longer opens the account.
    await expect((await w.device("bob")).vault.recover(bob.recoveryPhrase, "7777")).rejects.toEqual(code("WRONG_CREDENTIAL"));
    // The thief's keys were approved first in the team: the user's re-key needs a human (D-42).
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "rekey-unproven" }] });
  });

  it("TH-36: a session switches the account to a version with no real wraps; the version restore undoes it", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    await bob.store.commit([{ op: "set-account-key-version", accountId: "bob", expected: 1, accountKeyVersion: 2 }]);
    bob.vault.lock();
    await expect(bob.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    w.server.restoreVersion("bob", 1);
    await bob.vault.unlock();
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("Limit (TH-48): restoring a revoked device's wrap lets that device unlock again", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    const other = await w.device("bob");
    await other.vault.unlockWithPin(bob.pin);
    const { deviceId } = await other.vault.status();
    other.vault.lock();
    await bob.vault.revokeDevice(deviceId!);
    await expect(other.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    w.server.restore({ type: "account-key-wrap", accountId: "bob", accountKeyVersion: 1, method: "device", deviceId: deviceId! });
    await other.vault.unlock();
    expect(other.vault.isUnlocked).toBe(true);
  });
});

describe("SP-26: a record that fails its checks stops nothing (D-58, review 016 B)", () => {
  const garbageWrap = (teamId: string, memberKeysVersion: number) => ({
    v: 1, suite: "cc1", type: "member-keys-wrap", accountId: "bob", teamId, memberKeysVersion, accountKeyVersion: 1,
    wrappedKeys: { nonce: b64(24), ciphertext: b64(97 + 16) },
  });
  const plant = (teamId: string, memberKeysVersion: number) => [
    { op: "create", key: { type: "member-keys", teamId, accountId: "bob", memberKeysVersion }, record: { ...forgeMemberKeys("bob", memberKeysVersion, strangerKeys()), teamId } },
    { op: "create", key: { type: "member-keys-wrap", accountId: "bob", teamId, memberKeysVersion, accountKeyVersion: 1 }, record: garbageWrap(teamId, memberKeysVersion) },
  ] as const;

  it("a session's garbage wraps, for the team and for another, are absent: the remedy and the team still work", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    // A session publishes keys under bob's account with a garbage wrap, at the team's next version and in a team bob isn't in.
    const unparsable = [plant("team-y", 1)[0], { ...plant("team-y", 1)[1], record: { ...garbageWrap("team-y", 1), wrappedKeys: { nonce: b64(3), ciphertext: b64(3) } } }];
    await bob.store.commit([...plant("team-1", 2), ...plant("team-x", 1), ...unparsable] as never);
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
    expect(await bob.vault.warnings()).toContainEqual(expect.objectContaining({ code: "foreign-member-keys", teamIds: ["team-1"] }));
    const report = await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    expect(report).toEqual({ rekeyed: ["team-1"], failed: [] });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
  });

  it("the server refuses a wrap without its keys, or at another account key version, so a session can't take bob's next identity", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const wrapOnly = { op: "create", key: { type: "member-keys-wrap", accountId: "bob", teamId: "team-1", memberKeysVersion: 2, accountKeyVersion: 1 }, record: garbageWrap("team-1", 2) } as const;
    await expect(bob.store.commit([wrapOnly])).rejects.toThrow("member keys wrap without its member keys");
    const id = { type: "account-key-wrap", accountId: "bob", accountKeyVersion: 1, method: "recovery" } as const;
    const current = (await bob.store.get(id)) as Record<string, unknown>;
    const next = { op: "create", key: { ...id, accountKeyVersion: 2 }, record: { ...current, accountKeyVersion: 2 } } as never;
    await expect(bob.store.commit([next])).rejects.toThrow("wrap at another account key version");
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    expect((await bundleOf(bob.vault)).memberKeysVersion).toBe(2);
  });

  it("Accepted (TH-20): a wrap that opens with keys its record doesn't match fails its team, not the account", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const held = await bundleOf(bob.vault);
    const { ports, account } = vaultInternals(bob.vault);
    // An account-key holder wraps bob's own bundle at a new version, under keys someone else published.
    const context = { accountId: "bob", teamId: "team-1", memberKeysVersion: 2, accountKeyVersion: account().version };
    const raw = { signingSeed: held.pairs.signing.secretKey.subarray(0, 32), encryptionSecretKey: held.pairs.encryption.secretKey, teamStateKey: held.pairs.teamStateKey };
    await ports.store.commit([
      { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) },
      { op: "create", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(createMemberKeysWrap(cc1, context, account().key, raw)) },
    ]);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("key_mismatch"));
    // The rotation re-wraps it without checking, so securing the account still runs; that team is reported.
    expect(await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" })).toEqual({ rekeyed: [], failed: ["team-1"] });
  });

  describe("a team whose bundles fail stops only that team, not the warnings or a phrase replacement (D-58, review 028 A)", () => {
    const setup = async () => {
      const { members } = await team("bob");
      const bob = members.bob!;
      await bob.vault.createTeam("team-2");
      return bob;
    };
    const replacePhraseReport = async (bob: Awaited<ReturnType<typeof setup>>) => {
      const { recoveryPhrase } = bob.vault.beginRecoverySetup();
      return bob.vault.confirmRecoveryPhrase(recoveryPhrase, { currentPhrase: bob.recoveryPhrase });
    };

    it("a wrap planted with the account key that its published keys don't match", async () => {
      const bob = await setup();
      const held = await bundleOf(bob.vault);
      const { ports, account } = vaultInternals(bob.vault);
      const context = { accountId: "bob", teamId: "team-1", memberKeysVersion: 2, accountKeyVersion: account().version };
      const raw = { signingSeed: held.pairs.signing.secretKey.subarray(0, 32), encryptionSecretKey: held.pairs.encryption.secretKey, teamStateKey: held.pairs.teamStateKey };
      await ports.store.commit([
        { op: "create", key: { type: "member-keys", teamId: "team-1", accountId: "bob", memberKeysVersion: 2 }, record: forgeMemberKeys("bob", 2, strangerKeys()) },
        { op: "create", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(createMemberKeysWrap(cc1, context, account().key, raw)) },
      ]);
      expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("key_mismatch"));
      expect(await bob.vault.warnings()).toContainEqual(expect.objectContaining({ code: "foreign-member-keys", teamIds: ["team-1"] }));
      expect(await replacePhraseReport(bob)).toEqual({ rekeyed: ["team-2"], failed: ["team-1"] });
      expect((await bundleOf(bob.vault, "team-2")).memberKeysVersion).toBe(2);
    });

    it("a published record the server withholds", async () => {
      const bob = await setup();
      bob.store.drop({ type: "member-keys", teamId: "team-2", accountId: "bob" });
      expect(await bob.vault.warnings()).toContainEqual(expect.objectContaining({ code: "foreign-member-keys", teamIds: ["team-2"] }));
      expect(await replacePhraseReport(bob)).toEqual({ rekeyed: ["team-1"], failed: ["team-2"] });
    });
  });
});
