/**
 * SP-11: The account key can be rotated.
 * SP-25: An open vault alone can't change the account's credentials (rotation needs the phrase).
 * SP-07: the member keys' anchor floor moves to the newest trusted anchor at rotations and re-keys (D-50),
 * from the account's own records, never the device's local anchor (D-51).
 * Threats: TH-04, TH-10, TH-12, TH-20, TH-45.
 */
import { describe, expect, it } from "vitest";
import { openAccountKeyWrap, parseAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { world } from "../support/fixtures.js";
import { bundleOf } from "../support/forge.js";
import { accessOf } from "../support/forge.js";
import { team } from "../support/teams.js";
import { openBundles } from "../../src/account/member-custody.js";
import { vaultInternals, type Vault } from "../../src/account/vault.js";
import { createTeamKeyVersion, parseTeamKeyVersion, recordHash, teamKeyVersionToJson } from "../../src/records/team-key-version.js";
import { keysHash } from "../../src/records/member-keys.js";
import { cc1 } from "../../src/suites/cc1/index.js";
import type { RecordStore } from "../../src/ports.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { versionRecord } from "../support/forge.js";

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

  it("SP-07: the floor moves to the newest trusted anchor at a rotation and a re-key (D-50)", async () => {
    const { members, aliceTeam } = await team("bob");
    const alice = members.alice!;
    expect((await bundleOf(alice.vault)).floor?.version).toBe(1);
    await alice.vault.rotate({ phrase: alice.recoveryPhrase });
    expect((await bundleOf(alice.vault)).floor).toEqual(await anchorAt(alice.store, 2));
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    (await alice.vault.openTeam("team-1")).close();
    await alice.vault.rekey("team-1", { phrase: alice.recoveryPhrase });
    expect((await bundleOf(alice.vault)).floor).toEqual(await anchorAt(alice.store, 3));
  });

  it("SP-07: a rotation gives every bundle of a team the newest anchor any of them reads (D-50)", async () => {
    const { members, aliceTeam, w } = await team("bob");
    const bob = members.bob!;
    // A device with no local anchors: the floor comes from the bundles and the team-state.
    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin(bob.pin);
    await phone.vault.rekey("team-1");
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    // Bob's laptop writes the team-state at version 3 under the newest bundle's key only.
    (await bob.vault.openTeam("team-1")).close();
    await phone.vault.rotate({ phrase: bob.recoveryPhrase, newPin: bob.pin });
    const floors = (await bundlesOf(phone.vault)).map((b) => b.floor);
    expect(floors).toHaveLength(2);
    for (const floor of floors) expect(floor).toEqual(await anchorAt(bob.store, 3));
  });
});

describe("SP-07: a local anchor changed on the device never reaches the floor (D-51)", () => {
  it("a garbage local anchor stays out of the floor at a re-key and at secureAccount; a new device opens the team", async () => {
    const { members, w } = await team("bob");
    const bob = members.bob!;
    const floor = (await bundleOf(bob.vault)).floor;
    // A script or a thief on bob's laptop writes the local anchor (A9, A7).
    await bob.localKeys.setAnchor("bob", "team-1", { version: 50, hash: cc1.randomBytes(32) });
    await bob.vault.rekey("team-1");
    expect((await bundleOf(bob.vault)).floor).toEqual(floor);
    await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: bob.pin });
    for (const b of await bundlesOf(bob.vault)) expect(b.floor).toEqual(floor);
    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin(bob.pin);
    expect((await phone.vault.openTeam("team-1")).state).not.toBe("failed");
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
    await bob.vault.secureAccount({ phrase: bob.recoveryPhrase, newPin: bob.pin });
    expect((await bundleOf(bob.vault)).floor).not.toEqual(forgedAnchor);

    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin(bob.pin);
    phone.store.drop({ type: "team-state", accountId: "bob", teamId: "team-1" }).rollback("team-1", 1).fork("team-1", 9, forged);
    expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
  });
});
