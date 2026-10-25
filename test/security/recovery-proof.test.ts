/**
 * SP-23: A re-key proven by the recovery key is approved without an out-of-band check.
 * Threats: TH-10, TH-12, TH-13, TH-37, TH-41.
 */
import { describe, expect, it } from "vitest";
import { deriveRecoveryKeys } from "../../src/account/recovery-key.js";
import type { WireRecord, WriteOp } from "../../src/ports.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import { replacePhrase } from "../support/fixtures.js";
import { vaultInternals, type Vault } from "../../src/account/vault.js";
import { openRecoveryPublicKey, parseAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { b64 } from "../../src/encoding/json.js";
import { wrap } from "../../src/blocks/wrap.js";
import { string, u32 } from "../../src/encoding/canonical.js";
import { accessOf, bundleOf, forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

const phraseKey = (accountId: string, phrase: string) => deriveRecoveryKeys(cc1, accountId, phrase).signing.publicKey;

const create = (accountId: string, memberKeysVersion: number, record: WireRecord): WriteOp => ({
  op: "create",
  key: { type: "member-keys", teamId: "team-1", accountId, memberKeysVersion },
  record,
});

describe("SP-23: recovery-proven re-keys", () => {
  it("a re-key with the phrase is approved by reconcile; the old keys open nothing new", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const old = await bundleOf(bob.vault);
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    expect((await aliceTeam.owner().overview(["alice", "bob"])).accounts.find((a) => a.accountId === "bob")!.proof).toBe("recovery");

    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ rotatedTo: 3, approvedRekeys: ["bob"], needsHuman: [] });
    const access = (await accessOf(bob.store, "bob", 3))!;
    expect(access.memberKeysVersion).toBe(2);
    expect(() => access.open(old.pairs.encryption)).toThrow(expect.objectContaining({ code: "DECRYPTION_FAILED" }));
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });

  it("a session thief without the phrase gets a hint at most", async () => {
    const { members, aliceTeam } = await team("bob");
    const stolen = await bundleOf(members.bob!.vault);
    await members.bob!.store.commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys()))]);
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "rekey-unproven", proof: "none" }] });
  });

  it("a recovery signature by a key other than the held keys' one proves nothing", async () => {
    const { members, aliceTeam } = await team("bob");
    // The thief signs with a recovery key of its own, and names it in the record.
    const own = cc1.signingKeyPair(cc1.randomBytes(32));
    await members.bob!.store.commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys(), { recoverySigner: own }))]);
    expect((await aliceTeam.owner().reconcile(["alice", "bob"])).needsHuman).toEqual([
      { accountId: "bob", reason: "rekey-unproven", keys: expect.objectContaining({ accountId: "bob", memberKeysVersion: 2 }), proof: "none" },
    ]);
  });

  it("an owner's proven re-key still needs another owner's approval", async () => {
    const { members, aliceTeam } = await team("bob");
    await aliceTeam.owner().setOwners(["alice", "bob"]);
    await members.bob!.vault.rekey("team-1", { phrase: members.bob!.recoveryPhrase });
    const report = await aliceTeam.owner().reconcile(["alice", "bob"]);
    expect(report).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "owner-rekey", proof: "recovery" }] });
    await aliceTeam.owner().approve([report.needsHuman[0]!.keys!]);
    expect((await members.bob!.vault.openTeam("team-1")).ownerChanges.at(-1)).toMatchObject({ rekeyed: ["bob"] });
  });

  it("Limit (TH-41): a leaked phrase proves the thief's keys, and the real member is cut out", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const held = await bundleOf(bob.vault);
    const { signing } = deriveRecoveryKeys(cc1, "bob", bob.recoveryPhrase);
    await bob.store.commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys(), { recovery: held.published.recoveryPublicKey, recoverySigner: signing }))]);
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
    // Detected, not prevented: bob's own keys hold nothing current any more.
    expect((await bob.vault.openTeam("team-1")).state).toBe("pending");
  });

  it("a phrase replaced with the PIN instead of the old one re-keys every team without proof (D-41)", async () => {
    const { members, aliceTeam } = await team("bob");
    const { report } = await replacePhrase(members.bob!.vault, { currentPin: members.bob!.pin });
    expect(report).toEqual({ rekeyed: ["team-1"], failed: [] });
    expect((await aliceTeam.owner().reconcile(["alice", "bob"])).needsHuman).toMatchObject([{ accountId: "bob", reason: "rekey-unproven" }]);
  });

  it("a phrase replaced with the old one re-keys every team with proof", async () => {
    const { members, aliceTeam } = await team("bob");
    await replacePhrase(members.bob!.vault, { currentPhrase: members.bob!.recoveryPhrase });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"], needsHuman: [] });
  });

  it("D-49, D-56: a team re-keyed without proof is retried proven with the new phrase and the old one; the keys carry the new one's key", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const { recoveryPhrase: newPhrase } = await replacePhrase(bob.vault, { currentPin: bob.pin });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "rekey-unproven" }] });
    // The old phrase alone is no longer current; `oldPhrase` needs `phrase`.
    await expect(bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase })).rejects.toMatchObject({ code: "WRONG_CREDENTIAL" });
    await expect(bob.vault.rekey("team-1", { oldPhrase: bob.recoveryPhrase })).rejects.toMatchObject({ code: "MALFORMED_RECORD" });
    const other = (await team("x")).members.x!.recoveryPhrase;
    await expect(bob.vault.rekey("team-1", { phrase: newPhrase, oldPhrase: other })).rejects.toMatchObject({ code: "WRONG_CREDENTIAL" });
    await bob.vault.rekey("team-1", { phrase: newPhrase, oldPhrase: bob.recoveryPhrase });
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
    expect((await bundleOf(bob.vault)).published.recoveryPublicKey).toEqual(phraseKey("bob", newPhrase));
  });
});

describe("SP-23: the server can't choose the recovery key a proof is checked against (review 009 A)", () => {
  it("a record served for a held version must have the roster's keys hash, else nothing is approved", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const attacker = strangerKeys();
    const fakeRecovery = cc1.signingKeyPair(cc1.randomBytes(32));
    // Bait at bob's next version, proven by the attacker's recovery key (A2, or A11 through the server rule).
    await w.server.as("bob").commit([create("bob", 2, forgeMemberKeys("bob", 2, attacker, { recoverySigner: fakeRecovery }))]);
    // A2 serves, for bob's held version, a record naming the attacker's recovery key.
    members.alice!.store.replace({ type: "member-keys", accountId: "bob", memberKeysVersion: 1 }, forgeMemberKeys("bob", 1, strangerKeys(), { recovery: fakeRecovery.publicKey }));
    await expect(aliceTeam.owner().reconcile(["alice", "bob"])).rejects.toMatchObject({ code: "TRUST_FAILURE", reason: "key_mismatch" });
    members.alice!.store.reset();
    // No rotation was written.
    expect(await members.alice!.store.get({ type: "team-key-version", teamId: "team-1", version: 3 })).toBeNull();
  });

  it("overview doesn't show such a re-key as proven either", async () => {
    const { members, w } = await team("bob");
    const owner = (await members.alice!.vault.openTeam("team-1")).owner();
    const fakeRecovery = cc1.signingKeyPair(cc1.randomBytes(32));
    await w.server.as("bob").commit([create("bob", 2, forgeMemberKeys("bob", 2, strangerKeys(), { recoverySigner: fakeRecovery }))]);
    members.alice!.store.replace({ type: "member-keys", accountId: "bob", memberKeysVersion: 1 }, forgeMemberKeys("bob", 1, strangerKeys(), { recovery: fakeRecovery.publicKey }));
    await expect(owner.overview(["alice", "bob"])).rejects.toMatchObject({ code: "TRUST_FAILURE", reason: "key_mismatch" });
  });
});


describe("SP-23: the vault signs only for the phrase typed, never the recovery key the wrap names (D-56, review 013 B)", () => {
  /** A7 or A9 in the vault, with the session: keeps `wrappedAccountKey`, rewrites the public key it names. */
  async function splice(vault: Vault, accountId: string) {
    const { ports, account } = vaultInternals(vault);
    const { version, key } = account();
    const attacker = cc1.signingKeyPair(cc1.randomBytes(32));
    const id = { type: "account-key-wrap", accountId, accountKeyVersion: version, method: "recovery" } as const;
    const current = (await ports.store.get(id)) as Record<string, unknown>;
    const w = wrap(cc1, key, "recovery-public-key", [string(accountId), u32(version)], attacker.publicKey);
    await ports.store.commit([{ op: "replace", key: id, record: { ...current, wrappedRecoveryPublicKey: { nonce: b64(w.nonce), ciphertext: b64(w.ciphertext) } } }]);
    return attacker;
  }
  const storedKey = async (vault: Vault, accountId: string) => {
    const { ports, account } = vaultInternals(vault);
    const json = await ports.store.get({ type: "account-key-wrap", accountId, accountKeyVersion: account().version, method: "recovery" });
    return openRecoveryPublicKey(parseAccountKeyWrap(json, { accountId, accountKeyVersion: account().version, method: "recovery" }), account().key);
  };
  const mismatch = { code: "recovery-key-mismatch", teamIds: [], action: "secureAccount" };

  it("rekey with the real phrase signs keys carrying its key, reports the splice, and the attacker's proofs prove nothing", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const attacker = await splice(bob.vault, "bob");
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase });
    expect((await bundleOf(bob.vault)).published.recoveryPublicKey).toEqual(phraseKey("bob", bob.recoveryPhrase));
    expect(await bob.vault.warnings()).toContainEqual(mismatch);
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
    // The attacker's own re-key, signed by the recovery key it spliced in, stays unproven.
    await bob.store.commit([create("bob", 3, forgeMemberKeys("bob", 3, strangerKeys(), { recoverySigner: attacker }))]);
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: [], needsHuman: [{ accountId: "bob", reason: "rekey-unproven" }] });
  });

  it("secureAccount accepts the real phrase, rewrites the wrap from it, and its re-keys are proven", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await splice(bob.vault, "bob");
    const report = await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    expect(report).toEqual({ rekeyed: ["team-1"], failed: [] });
    expect(await storedKey(bob.vault, "bob")).toEqual(phraseKey("bob", bob.recoveryPhrase));
    expect((await bundleOf(bob.vault)).published.recoveryPublicKey).toEqual(phraseKey("bob", bob.recoveryPhrase));
    expect(await bob.vault.warnings()).not.toContainEqual(mismatch);
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
  });

  it("with a new phrase, the re-keys carry the typed new phrase's key, proven by the current one", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await splice(bob.vault, "bob");
    const { recoveryPhrase: newPhrase } = bob.vault.beginRecoverySetup();
    await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPhrase, newPin: "5678" });
    expect((await bundleOf(bob.vault)).published.recoveryPublicKey).toEqual(phraseKey("bob", newPhrase));
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
  });

  it("confirmRecoveryPhrase with the current phrase still works and proves the re-keys", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await splice(bob.vault, "bob");
    const { recoveryPhrase: newPhrase, report } = await replacePhrase(bob.vault, { currentPhrase: bob.recoveryPhrase });
    expect(report.failed).toEqual([]);
    expect((await bundleOf(bob.vault)).published.recoveryPublicKey).toEqual(phraseKey("bob", newPhrase));
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
  });

  it("recover opens the account with the real phrase and reports the splice", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    await splice(bob.vault, "bob");
    const phone = await w.device("bob");
    await phone.vault.recover(bob.recoveryPhrase, "5678");
    expect(phone.vault.isUnlocked).toBe(true);
    expect(await phone.vault.warnings()).toContainEqual(mismatch);
  });

  it("a phrase that doesn't open the recovery wrap is refused before anything is written", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const other = (await team("x")).members.x!.recoveryPhrase;
    const before = await bundleOf(bob.vault);
    await expect(bob.vault.rekey("team-1", { phrase: other })).rejects.toMatchObject({ code: "WRONG_CREDENTIAL" });
    await expect(bob.vault.secureAccount({ phrase: other })).rejects.toMatchObject({ code: "WRONG_CREDENTIAL" });
    expect((await bundleOf(bob.vault)).memberKeysVersion).toBe(before.memberKeysVersion);
  });
});

describe("SP-23: a recovery wrap a session garbled is a mismatch, never a refusal (D-56, review 032 A)", () => {
  const recoveryKey = { type: "account-key-wrap", accountId: "bob", accountKeyVersion: 1, method: "recovery" } as const;
  const flip = (value: string) => {
    const bytes = Buffer.from(value, "base64url");
    bytes[0]! ^= 1;
    return bytes.toString("base64url");
  };

  it("a stored public key that doesn't open: reported, and secureAccount repairs it", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const stored = (await bob.store.get(recoveryKey)) as Record<string, { nonce: string; ciphertext: string }>;
    const garbled = { ...stored, wrappedRecoveryPublicKey: { ...stored.wrappedRecoveryPublicKey!, ciphertext: flip(stored.wrappedRecoveryPublicKey!.ciphertext) } };
    await bob.store.commit([{ op: "replace", key: recoveryKey, record: garbled }]);
    expect(await bob.vault.warnings()).toContainEqual(expect.objectContaining({ code: "recovery-key-mismatch", action: "secureAccount" }));
    expect(await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" })).toEqual({ rekeyed: ["team-1"], failed: [] });
    expect(await bob.vault.warnings()).not.toContainEqual(expect.objectContaining({ code: "recovery-key-mismatch" }));
    expect((await bundleOf(bob.vault)).published.recoveryPublicKey).toEqual(phraseKey("bob", bob.recoveryPhrase));
  });

  it("a recovery wrap that doesn't parse: reported, and a setup with the PIN replaces it", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const stored = (await bob.store.get(recoveryKey)) as Record<string, unknown>;
    await bob.store.commit([{ op: "replace", key: recoveryKey, record: { ...stored, extra: 1 } }]);
    expect(await bob.vault.warnings()).toContainEqual(expect.objectContaining({ code: "recovery-key-mismatch" }));
    const { recoveryPhrase } = bob.vault.beginRecoverySetup();
    expect(await bob.vault.confirmRecoveryPhrase(recoveryPhrase, { currentPin: "1234" })).toEqual({ rekeyed: ["team-1"], failed: [] });
    expect(await bob.vault.warnings()).not.toContainEqual(expect.objectContaining({ code: "recovery-key-mismatch" }));
  });
});
