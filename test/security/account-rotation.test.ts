/**
 * SP-11: The account key can be rotated.
 * SP-25: An open vault alone can't change the account's credentials (rotation needs the phrase).
 * SP-07: the member keys' anchor floor is the root of trust: it moves only along a chain verified from
 * it (vault open or export, re-key) where every root agrees, a rotation keeps it, nothing written outside the
 * vault reaches it, and an owner's anchor repairs it (D-52, D-54).
 * Threats: TH-04, TH-10, TH-12, TH-20, TH-45.
 */
import { describe, expect, it } from "vitest";
import { openAccountKeyWrap, parseAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { FAST, world } from "../support/fixtures.js";
import { bundleOf } from "../support/forge.js";
import { accessOf } from "../support/forge.js";
import { team } from "../support/teams.js";
import { openBundles } from "../../src/account/member-custody.js";
import { createVault, vaultInternals, type Vault } from "../../src/account/vault.js";
import { createMemberKeysWrap, memberKeysWrapToJson } from "../../src/records/member-keys-wrap.js";
import { createTeamKeyReceiver } from "../../src/team/receiver.js";
import { createTeamKeyVersion, parseTeamKeyVersion, recordHash, teamKeyVersionToJson } from "../../src/records/team-key-version.js";
import { keysHash } from "../../src/records/member-keys.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import type { OprfPurpose, OprfService, RecordStore } from "../../src/ports.js";
import { RateLimitedError } from "../../src/errors.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { versionRecord, forgeFirstVersion, forgeVersion } from "../support/forge.js";
import type { TamperingStore } from "../support/fake-store.js";

const bundlesOf = (vault: Vault) => openBundles(vaultInternals(vault).ports, vaultInternals(vault).account(), "team-1");
const anchorAt = async (store: RecordStore, version: number) => ({ version, hash: recordHash(await versionRecord(store, "team-1", version)) });

const code = (c: string) => expect.objectContaining({ code: c });
const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });

describe("SP-11: the account key can be rotated", () => {
  it("keeps the PIN and phrase working, and makes other devices register again", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const phone = await w.device("alice");
    await phone.vault.unlockWithPin("1234");

    await laptop.vault.rotate({ phrase: laptop.recoveryPhrase, newPin: "1234" });
    expect((await laptop.vault.status()).recovery).toBe("set-up");
    laptop.vault.lock();
    await laptop.vault.unlock();

    phone.vault.lock();
    await expect(phone.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    await phone.vault.unlockWithPin("1234");
    await (await w.device("alice")).vault.recover(laptop.recoveryPhrase, "1234");
  });

  it("SP-25: refuses a rotation without the phrase; with it, recovery stays set up (D-41)", async () => {
    const w = world();
    const laptop = await w.account("alice");
    await expect(laptop.vault.rotate({} as never)).rejects.toEqual(code("MALFORMED_RECORD"));
    await expect(laptop.vault.rotate({ newPin: "1234" } as never)).rejects.toEqual(code("MALFORMED_RECORD"));
    expect(await laptop.store.getAccountKeyVersion("alice")).toBe(1);
    await laptop.vault.rotate({ phrase: laptop.recoveryPhrase });
    expect((await laptop.vault.status()).recovery).toBe("set-up");
    await laptop.vault.createTeam("team-1");
    await (await w.device("alice")).vault.recover(laptop.recoveryPhrase, "1");
  });

  it("refuses a mistyped phrase before changing anything", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const { recoveryPhrase: other } = await w.account("bob");
    await expect(laptop.vault.rotate({ phrase: other, newPin: "1234" })).rejects.toEqual(code("WRONG_CREDENTIAL"));
    expect(await laptop.store.getAccountKeyVersion("alice")).toBe(1);
  });

  it("the old account key opens no record written after the rotation", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const deviceWrap = await laptop.store.list({ type: "account-key-wrap", accountId: "alice", accountKeyVersion: 1 });
    const device = (await laptop.localKeys.getDevice("alice"))!;
    const v1 = deviceWrap.map((j) => parseAccountKeyWrap(j, { accountId: "alice", accountKeyVersion: 1, method: (j as { method: "pin" }).method })).find((x) => x.method === "device")!;
    const oldKey = openAccountKeyWrap(v1, device.deviceKey);

    await laptop.vault.rotate({ phrase: laptop.recoveryPhrase, newPin: "1234" });
    const after = w.server.dump().filter((r) => r["accountKeyVersion"] === 2);
    expect(after.length).toBeGreaterThan(0);
    for (const json of after) {
      const wrap = parseAccountKeyWrap(json, { accountId: "alice", accountKeyVersion: 2, method: json["method"] as "pin" });
      expect(() => openAccountKeyWrap(wrap, oldKey)).toThrow();
    }
  });
});

describe("SP-11: teams survive an account key rotation", () => {
  it("every team still opens with the new key, and member keys are unchanged", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const before = await bundleOf(bob.vault);
    await bob.vault.rotate({ phrase: bob.recoveryPhrase, newPin: bob.pin });
    const session = await bob.vault.openTeam("team-1");
    expect(session.state).toBe("ready");
    const after = await bundleOf(bob.vault);
    expect(Buffer.from(after.pairs.signing.publicKey).equals(Buffer.from(before.pairs.signing.publicKey))).toBe(true);
  });

  it("Limit: a copied member keys bundle keeps opening the team until a re-key", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const copied = await bundleOf(bob.vault);
    await bob.vault.rotate({ phrase: bob.recoveryPhrase, newPin: bob.pin });
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    expect((await accessOf(bob.store, "bob", 2))!.open(copied.pairs.encryption)).toHaveLength(32);
  });

  it("SP-07: a rotation keeps each bundle's floor; a vault open and a re-key move it along the verified chain (D-52)", async () => {
    const { members, aliceTeam } = await team("bob");
    const alice = members.alice!;
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    const before = (await bundleOf(alice.vault)).floor!;
    expect(before.version).toBeLessThan(3);
    await alice.vault.rotate({ phrase: alice.recoveryPhrase });
    expect((await bundleOf(alice.vault)).floor).toEqual(before);
    (await alice.vault.openTeam("team-1")).close();
    expect((await bundleOf(alice.vault)).floor).toEqual(await anchorAt(alice.store, 3));
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    await alice.vault.rekey("team-1", { phrase: alice.recoveryPhrase });
    expect((await bundleOf(alice.vault)).floor).toEqual(await anchorAt(alice.store, 4));
  });

  it("SP-07: exporting the team moves the floor too, so split layouts keep it near the tip (D-52)", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    const receiver = await createTeamKeyReceiver("bob", "team-1");
    await bob.vault.exportTeamKeys("team-1", receiver.request);
    expect((await bundleOf(bob.vault)).floor).toEqual(await anchorAt(bob.store, 3));
  });

  it("SP-07: a re-key whose chain doesn't verify from its roots writes nothing (D-54)", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    const before = await bundleOf(bob.vault);
    bob.store.rollback("team-1", before.floor!.version - 1);
    await expect(bob.vault.rekey("team-1")).rejects.toEqual(trust("rollback"));
    expect((await bundleOf(bob.vault)).memberKeysVersion).toBe(before.memberKeysVersion);
  });

  /** A9 in the vault or A7: the account key and a session; the newest wrap, same keys, a planted floor. */
  async function plantFloor(vault: Vault) {
    const held = await bundleOf(vault);
    const { ports, account } = vaultInternals(vault);
    const context = { accountId: "bob", teamId: "team-1", memberKeysVersion: held.memberKeysVersion, accountKeyVersion: account().version };
    const raw = { signingSeed: held.pairs.signing.secretKey.subarray(0, 32), encryptionSecretKey: held.pairs.encryption.secretKey, teamStateKey: held.pairs.teamStateKey, floor: { version: 50, hash: cc1.randomBytes(32) } };
    await ports.store.commit([{ op: "replace", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(createMemberKeysWrap(cc1, context, account().key, raw)) }]);
  }

  it("SP-07, TH-20: a planted floor fails its team at secureAccount, and an owner's anchor repairs it (D-54)", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    await plantFloor(bob.vault);
    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin(bob.pin);
    expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("rollback"));

    // The vault's own anchor disagrees with the planted floor: the team is reported, nothing is carried.
    const report = await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    expect(report.failed).toEqual(["team-1"]);
    // An owner sends the team's anchor out of band; it is the only root of the repair.
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase, anchor: aliceTeam.inviteAnchor() });
    expect((await bundleOf(bob.vault)).floor).toEqual(await anchorAt(bob.store, 2));
    const later = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await later.vault.unlockWithPin("5678");
    expect((await later.vault.openTeam("team-1")).failure).toBeUndefined();
  });

  it("SP-07: in a split layout too, the vault's anchor refuses a planted floor, and export refuses to seal it (review 009 B)", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    // The split layout's vault: no `anchors`; it records its own anchor when it exports.
    const vault = await createVault({ store: bob.store, oprf: w.oprf, deviceKeys: bob.localKeys, clock: w.clock, settings: { ...FAST, oprf: await w.oprf.clientSettings() } }, "bob");
    await vault.unlock();
    await vault.exportTeamKeys("team-1", (await createTeamKeyReceiver("bob", "team-1")).request);
    await plantFloor(vault);
    await expect(vault.exportTeamKeys("team-1", (await createTeamKeyReceiver("bob", "team-1")).request)).rejects.toEqual(trust("rollback"));
    const report = await vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    expect(report.failed).toEqual(["team-1"]);
  });

  it("Limit (TH-20): a vault with no anchor of its own verifies from the floor it holds; an owner's anchor repairs it (D-54)", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    const fresh = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await fresh.vault.unlockWithPin(bob.pin);
    await plantFloor(fresh.vault);
    // A forged vault anchor too: the owner's anchor must replace it, even though it is higher.
    await fresh.localKeys.setVaultAnchor("bob", "team-1", { version: 60, hash: cc1.randomBytes(32) });
    // Honest server: the planted floor isn't on the chain, so the team fails rather than carrying it.
    const report = await fresh.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    expect(report.failed).toEqual(["team-1"]);
    await fresh.vault.rekey("team-1", { phrase: bob.recoveryPhrase, anchor: aliceTeam.inviteAnchor() });
    expect((await bundleOf(fresh.vault)).floor).toEqual(await anchorAt(bob.store, 2));
    expect(await fresh.localKeys.getVaultAnchor("bob", "team-1")).toEqual(await anchorAt(bob.store, 2));
  });

  it("SP-07, TH-20: with the server, a planted floor naming a forged version still fails against the vault's anchor (D-54)", async () => {
    const t = await team("bob");
    const bob = t.members.bob!;
    (await bob.vault.openTeam("team-1")).close(); // the vault's anchor: version 2
    const mallory = await t.w.account("mallory");
    await mallory.vault.joinTeam("team-1");
    const m = await bundleOf(mallory.vault);
    const v = await bundleOf(bob.vault);
    const entry = (accountId: string, b: typeof m) => ({ accountId, memberKeysVersion: b.memberKeysVersion, keysHash: keysHash(cc1, b.published), encryptionPublicKey: b.pairs.encryption.publicKey });
    const forged = teamKeyVersionToJson(
      createTeamKeyVersion(cc1, {
        teamId: "team-1", version: 9, prevHash: cc1.randomBytes(32),
        owners: [{ accountId: "mallory", signingPublicKey: m.pairs.signing.publicKey }],
        roster: [entry("mallory", m), entry("bob", v)], createdAt: 1,
        signer: { accountId: "mallory", signingPublicKey: m.pairs.signing.publicKey },
        signerSecretKey: m.pairs.signing.secretKey, teamKey: cc1.randomBytes(32), previousKey: cc1.randomBytes(32),
      }),
    );
    const forgedAnchor = { version: 9, hash: recordHash(parseTeamKeyVersion(forged, { teamId: "team-1" })) };
    // Plant the forged anchor as the floor, and serve the forged version (A2).
    const { ports, account } = vaultInternals(bob.vault);
    const context = { accountId: "bob", teamId: "team-1", memberKeysVersion: v.memberKeysVersion, accountKeyVersion: account().version };
    const raw = { signingSeed: v.pairs.signing.secretKey.subarray(0, 32), encryptionSecretKey: v.pairs.encryption.secretKey, teamStateKey: v.pairs.teamStateKey, floor: forgedAnchor };
    await ports.store.commit([{ op: "replace", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(createMemberKeysWrap(cc1, context, account().key, raw)) }]);
    bob.store.fork("team-1", 9, forged);
    const report = await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    expect(report.failed).toEqual(["team-1"]);
    expect((await bundleOf(bob.vault)).floor).toEqual(forgedAnchor); // the old bundle, re-wrapped: reported, not re-keyed
  });

  it("refuses a secureAccount PIN that opens the current PIN wrap: the retired version would open with it (SP-19)", async () => {
    const { members } = await team("bob");
    const bob = members.bob!;
    await expect(bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: bob.pin })).rejects.toEqual(code("MALFORMED_RECORD"));
    expect(await bob.store.getAccountKeyVersion("bob")).toBe(1);
  });

  it("with a budget split by purpose, the check draws on the share the new PIN does: the old PIN is never set unchecked (review 013 G)", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    // A server that splits the total budget by purpose (§5.1); `refused` is the spent share.
    let refused: OprfPurpose | null = null;
    const split: OprfService = { evaluate: (request) => (request.purpose === refused ? Promise.reject(new RateLimitedError()) : w.oprf.evaluate(request)) };
    const device = await w.device("bob", { oprf: split });
    await device.vault.unlockWithPin(bob.pin);
    // The unlock share spent, the enroll share open: the check still runs, and refuses.
    refused = "unlock";
    await expect(device.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: bob.pin })).rejects.toEqual(code("MALFORMED_RECORD"));
    // The enroll share spent: the check is skipped, and setting the PIN fails too; nothing is written.
    refused = "enroll";
    await expect(device.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: bob.pin })).rejects.toEqual(code("PIN_RATE_LIMITED"));
    expect(await bob.store.getAccountKeyVersion("bob")).toBe(1);
  });
});

describe("SP-07: a local anchor changed on the device never reaches the floor (D-51, D-52)", () => {
  it("a garbage local anchor stays out of the floor at a re-key and at secureAccount; a new device opens the team", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    // A script or a thief on bob's laptop writes the local anchor (A9, A7).
    await bob.localKeys.setAnchor("bob", "team-1", { version: 50, hash: cc1.randomBytes(32) });
    await bob.vault.rekey("team-1");
    // The floor follows the chain verified from the floor: the tip, version 2.
    const floor = await anchorAt(bob.store, 2);
    expect((await bundleOf(bob.vault)).floor).toEqual(floor);
    await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    // The sessions' anchor isn't one of the vault's roots: the floor follows the floor and the vault's anchor.
    expect((await bundleOf(bob.vault)).floor).toEqual(floor);
    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin("5678");
    expect((await phone.vault.openTeam("team-1")).failure).toBeUndefined();
  });

  it("with the server: a local anchor pointing at a forged version doesn't make new devices open it", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    const mallory = await w.account("mallory");
    await mallory.vault.joinTeam("team-1");
    const m = await bundleOf(mallory.vault);
    const v = await bundleOf(bob.vault);
    const entry = (accountId: string, b: typeof m) => ({
      accountId,
      memberKeysVersion: b.memberKeysVersion,
      keysHash: keysHash(cc1, b.published),
      encryptionPublicKey: b.pairs.encryption.publicKey,
    });
    // A version 9 the server forged: owned by mallory, rostering bob's real keys.
    const forged = teamKeyVersionToJson(
      createTeamKeyVersion(cc1, {
        teamId: "team-1",
        version: 9,
        prevHash: cc1.randomBytes(32),
        owners: [{ accountId: "mallory", signingPublicKey: m.pairs.signing.publicKey }],
        roster: [entry("mallory", m), entry("bob", v)],
        createdAt: 1,
        signer: { accountId: "mallory", signingPublicKey: m.pairs.signing.publicKey },
        signerSecretKey: m.pairs.signing.secretKey,
        teamKey: cc1.randomBytes(32),
        previousKey: cc1.randomBytes(32),
      }),
    );
    const forgedAnchor = { version: 9, hash: recordHash(parseTeamKeyVersion(forged, { teamId: "team-1" })) };
    await bob.localKeys.setAnchor("bob", "team-1", forgedAnchor);
    await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: "5678" });
    expect((await bundleOf(bob.vault)).floor).not.toEqual(forgedAnchor);

    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin("5678");
    phone.store.drop({ type: "team-state", accountId: "bob", teamId: "team-1" }).rollback("team-1", 1).fork("team-1", 9, forged);
    // Served from the floor, the forged version doesn't link to it.
    expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("rollback"));
  });
});

describe("SP-07: a join verifies from the vault's own anchor too (D-59, review 019 A)", () => {
  it("an existing member's join without an anchor refuses a forged chain when the server withholds its wraps; an owner's anchor repairs a team with no bundle", async () => {
    const { w, members, aliceTeam } = await team("bob");
    await aliceTeam.owner().rotate({ keep: ["bob"] }); // the real chain at v3
    const bob = members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    const real = await bob.localKeys.getVaultAnchor("bob", "team-1");
    expect(real?.version).toBe(3);

    // The server forges a chain owned by mallory, up to v4, and withholds bob's wraps (absent, D-58).
    const mallory = await w.account("mallory");
    await mallory.vault.joinTeam("team-1");
    const m = await bundleOf(mallory.vault);
    const owner = { accountId: "mallory", keys: m.pairs, published: m.published };
    const forks: unknown[] = [];
    const apply = (store: TamperingStore) => { store.rollback("team-1", 0); forks.forEach((f, i) => store.fork("team-1", i + 1, f)); };
    forks.push(forgeFirstVersion({ owner, roster: [owner] }));
    for (const v of [2, 3, 4]) { apply(bob.store.reset()); forks.push(await forgeVersion(bob.store, { version: v, owners: [owner], signer: owner })); }
    bob.store.reset(); apply(bob.store);
    bob.store.drop({ type: "member-keys-wrap", teamId: "team-1" });

    await expect(bob.vault.joinTeam("team-1")).rejects.toEqual(expect.objectContaining({ code: "TRUST_FAILURE" }));
    expect(await bob.localKeys.getVaultAnchor("bob", "team-1")).toEqual(real);

    // An owner's anchor re-keys the team though no wrap opens (here, withheld by the server): the repair.
    bob.store.reset();
    bob.store.drop({ type: "member-keys-wrap", teamId: "team-1" });
    await bob.vault.rekey("team-1", { phrase: bob.recoveryPhrase, anchor: aliceTeam.inviteAnchor() });
    bob.store.reset();
    expect(await aliceTeam.owner().reconcile(["alice", "bob"])).toMatchObject({ approvedRekeys: ["bob"] });
  });
});
