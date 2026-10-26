/**
 * SP-07: A client never goes back to an older team state, nor below its keys' floor (D-48, D-50).
 * Threats: TH-04, TH-05, TH-46.
 */
import { sessionInternals } from "../../src/team/session.js";
import { describe, expect, it } from "vitest";
import { cc1 } from "../../src/suites/cc1/index.js";
import { createTeamKeyReceiver } from "../../src/team/receiver.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { vaultInternals, type Vault } from "../../src/account/vault.js";
import { createTeamKeyVersion, parseTeamKeyVersion, recordHash, teamKeyVersionToJson } from "../../src/records/team-key-version.js";
import { keysHash } from "../../src/records/member-keys.js";
import { memberKeysWrapToJson } from "../../src/records/member-keys-wrap.js";
import { openTransfer } from "../../src/records/transfer.js";
import { wrap } from "../../src/blocks/wrap.js";
import { seal } from "../../src/blocks/seal.js";
import { bytes, list, optional, string, u32 } from "../../src/encoding/canonical.js";
import { toBase64url } from "../../src/encoding/base64url.js";
import { concat } from "../../src/internal/bytes.js";
import type { TamperingStore } from "../support/fake-store.js";
import { bundleOf, forgeFirstVersion, forgeVersion } from "../support/forge.js";
import { team } from "../support/teams.js";
import { ContentStore, addParts, read } from "../support/content-store.js";

const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });

async function threeVersions() {
  // Version 1 (alice), 2 (bob approved), 3 (a rotation).
  const t = await team("bob");
  await t.aliceTeam.owner().rotate({ keep: ["bob"] });
  const bob = t.members.bob!;
  expect((await bob.vault.openTeam("team-1")).currentVersion).toBe(3);
  return { ...t, bob };
}

describe("SP-07: a client never goes back", () => {
  it("an anchored client fetches the chain from its anchor, never below it", async () => {
    const { bob } = await threeVersions();
    const inner = bob.store.inner;
    const from: number[] = [];
    bob.store.inner = {
      get: (key) => inner.get(key),
      list: (query) => {
        if (query.type === "team-key-version") from.push(query.fromVersion);
        return inner.list(query);
      },
      getAccountKeyVersion: (accountId) => inner.getAccountKeyVersion(accountId),
      commit: (ops) => inner.commit(ops),
    };
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
    expect(from).toEqual([3]);
  });

  it("older versions are fetched on demand, pinned by the hash links of the verified chain", async () => {
    const t = await team("bob");
    const content = new ContentStore();
    await addParts(t.aliceTeam.beginItem(), content, "old", ["from version 2"]).seal("old");
    await t.aliceTeam.owner().rotate({ keep: ["bob"] });
    await (await t.members.alice!.vault.openTeam("team-1")).owner().rotate({ keep: ["bob"] });
    const bob = t.members.bob!;
    expect((await bob.vault.openTeam("team-1")).currentVersion).toBe(4);

    const session = await bob.vault.openTeam("team-1");
    expect(read(await (await session.openItem("old")).part(0, content.get("old", 0)))).toBe("from version 2");

    // A server that swaps a record below the anchor is caught by the hash link.
    const alice = await bundleOf(t.members.alice!.vault);
    bob.store.fork("team-1", 3, await forgeVersion(bob.store, { version: 3, owners: [{ ...alice, accountId: "alice", keys: alice.pairs }], signer: { ...alice, accountId: "alice", keys: alice.pairs } }));
    const later = await bob.vault.openTeam("team-1");
    expect(later.state).toBe("ready");
    await expect(later.openItem("old")).rejects.toEqual(trust("chain_conflict"));
    expect(later.state).toBe("unverified");
  });

  it("refuses a chain cut before its anchor", async () => {
    const { bob } = await threeVersions();
    bob.store.rollback("team-1", 2);
    const session = await bob.vault.openTeam("team-1");
    expect(session.failure).toEqual(trust("rollback"));
    expect(() => sessionInternals(session).writeVersion()).toThrow(trust("rollback"));
  });

  it("refuses a chain that diverges from its anchor", async () => {
    const { bob, members } = await threeVersions();
    const alice = await bundleOf(members.alice!.vault);
    bob.store.fork("team-1", 3, await forgeVersion(bob.store, { version: 3, owners: [{ ...alice, accountId: "alice", keys: alice.pairs }], signer: { ...alice, accountId: "alice", keys: alice.pairs } }));
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
  });

  it("a new device starts from its keys' floor, not first-contact trust (D-66)", async () => {
    const { w } = await threeVersions();
    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin("1234");
    phone.store.rollback("team-1", 2);
    expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("rollback"));
  });

  describe("D-66: every bundle holds a floor", () => {
    // The layouts before D-66: a team state key, then an optional floor (97 or 137 bytes).
    const retired = (seed: Uint8Array, secretKey: Uint8Array, floor: { version: number; hash: Uint8Array } | null) =>
      concat(seed, secretKey, cc1.randomBytes(32), optional(floor, (f) => concat(u32(f.version), bytes(f.hash))));

    it.each([
      ["without a floor (97 bytes)", false],
      ["with a floor (137 bytes)", true],
    ])("a bundle in the retired layout %s, planted with the account key, doesn't open: the team reads not-joined", async (_, withFloor) => {
      const { members } = await team("bob");
      const bob = members.bob!;
      const held = await bundleOf(bob.vault);
      const { ports, account } = vaultInternals(bob.vault);
      const context = { accountId: "bob", teamId: "team-1", memberKeysVersion: held.memberKeysVersion, accountKeyVersion: account().version };
      const plaintext = retired(held.pairs.signing.secretKey.subarray(0, 32), held.pairs.encryption.secretKey, withFloor ? held.floor : null);
      const ad = [string(context.accountId), string(context.teamId), u32(context.memberKeysVersion), u32(context.accountKeyVersion)];
      const record = { v: 1, suite: cc1, ...context, wrappedKeys: wrap(cc1, account().key, "member-keys-wrap", ad, plaintext) };
      await ports.store.commit([{ op: "replace", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(record) }]);
      expect((await bob.vault.openTeam("team-1")).state).toBe("not-joined");
    });

    it("a transfer entry without a floor, in the retired layout, is refused", () => {
      const receiver = cc1.generateEncryptionKeyPair();
      const entry = { version: 1, seed: cc1.randomBytes(32), secretKey: cc1.randomBytes(32) };
      const body = list([entry], (e) => concat(u32(e.version), bytes(e.seed), bytes(e.secretKey), bytes(cc1.randomBytes(32)), optional(null, () => new Uint8Array())));
      const transfer = "1" + toBase64url(seal(cc1, receiver.publicKey, "team-keys-transfer", [string("bob"), string("team-1")], body));
      expect(() => openTransfer(cc1, receiver, { accountId: "bob", teamId: "team-1" }, transfer)).toThrow(expect.objectContaining({ code: "MALFORMED_RECORD" }));
    });
  });

  it("a joiner's invite anchor is checked at join: a chain without it is refused before any key is written (D-48)", async () => {
    const { aliceTeam, w } = await team();
    await aliceTeam.owner().rotate({ keep: [] });
    const anchor = aliceTeam.inviteAnchor();
    const dave = await w.account("dave");
    dave.store.rollback("team-1", 1);
    await expect(dave.vault.joinTeam("team-1", { anchor })).rejects.toEqual(trust("rollback"));
    expect(await dave.store.list({ type: "member-keys", teamId: "team-1", accountId: "dave" })).toEqual([]);
    const erin = await w.account("erin");
    await erin.vault.joinTeam("team-1", { anchor });
    expect((await erin.vault.openTeam("team-1")).state).toBe("pending");
    expect((await bundleOf(erin.vault)).floor?.version).toBe(2);
  });

  it("a malformed invite anchor is refused at join, before anything is written", async () => {
    const { w } = await team();
    const dave = await w.account("dave");
    await expect(dave.vault.joinTeam("team-1", { anchor: "1not-an-anchor" })).rejects.toMatchObject({ code: "MALFORMED_RECORD" });
    await expect(dave.vault.joinTeam("team-1", { anchor: "9AAAA" })).rejects.toMatchObject({ code: "UNSUPPORTED_VERSION" });
    expect(await dave.store.list({ type: "member-keys", teamId: "team-1", accountId: "dave" })).toEqual([]);
  });

  describe("TH-04, TH-05: a device with no anchor starts from the member keys' floor (D-48)", () => {
    /** A forged team the server shows `victim`'s device: owned by mallory, rostering the victim's real keys. */
    async function forgedTeam(w: Awaited<ReturnType<typeof team>>["w"], victim: { vault: Vault; store: TamperingStore }, accountId: string) {
      const mallory = await w.account("mallory");
      await mallory.vault.joinTeam("team-1");
      const m = await bundleOf(mallory.vault);
      const owner = { accountId: "mallory", keys: m.pairs, published: m.published };
      const v = await bundleOf(victim.vault);
      const forged = forgeFirstVersion({ owner, roster: [owner, { accountId, keys: v.pairs, published: v.published }] });
      victim.store.rollback("team-1", 1).fork("team-1", 1, forged);
    }

    it("an existing member's new device refuses a forged team", async () => {
      const { w } = await team("bob");
      const fresh = await w.device("alice");
      await fresh.vault.unlockWithPin("1234");
      await forgedTeam(w, fresh, "alice");
      expect((await fresh.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
    });

    it("in a receiving context too (§3.8): the transfer carries the floor, moved to the tip at the export (D-52)", async () => {
      const { w } = await team("bob");
      const fresh = await w.device("alice");
      await fresh.vault.unlockWithPin("1234");
      const receiver = await createTeamKeyReceiver("alice", "team-1");
      const transfer = await fresh.vault.exportTeamKeys("team-1", receiver.request);
      await forgedTeam(w, fresh, "alice");
      const page = { store: fresh.store, anchors: new MemoryLocalKeyStore(), clock: w.clock };
      expect((await receiver.openTeam(page, transfer)).failure).toEqual(trust("rollback"));
    });

    it("a joiner without an invite anchor is protected from its join on: its floor is the chain verified at join (D-50)", async () => {
      const { w } = await team("bob");
      const fresh = await w.device("bob");
      await fresh.vault.unlockWithPin("1234");
      await forgedTeam(w, fresh, "bob");
      expect((await fresh.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
    });

    it("Limit (TH-04): without an invite anchor, the join is the first contact: a forged chain served then is trusted", async () => {
      const { w } = await team();
      const mallory = await w.account("mallory");
      await mallory.vault.joinTeam("team-1");
      const m = await bundleOf(mallory.vault);
      const owner = { accountId: "mallory", keys: m.pairs, published: m.published };
      const forged = forgeFirstVersion({ owner, roster: [owner] });
      const dave = await w.account("dave");
      dave.store.rollback("team-1", 1).fork("team-1", 1, forged);
      await dave.vault.joinTeam("team-1");
      expect((await bundleOf(dave.vault)).floor).toEqual({ version: 1, hash: recordHash(parseTeamKeyVersion(forged, { teamId: "team-1" })) });
    });

    it("the repair with an owner's anchor replaces this device's local anchor too: after a forged first contact, it opens the real chain (review 035 A)", async () => {
      const { w, aliceTeam } = await team();
      const mallory = await w.account("mallory");
      await mallory.vault.joinTeam("team-1");
      const m = await bundleOf(mallory.vault);
      const owner = { accountId: "mallory", keys: m.pairs, published: m.published };
      const forged = forgeFirstVersion({ owner, roster: [owner] });
      const dave = await w.account("dave");
      dave.store.rollback("team-1", 1).fork("team-1", 1, forged);
      await dave.vault.joinTeam("team-1");
      // dave opens the forged team: this device's local anchor now names it.
      (await dave.vault.openTeam("team-1")).close();
      // The server turns honest; an owner gives dave the real anchor out of band.
      dave.store.reset();
      expect((await dave.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
      await dave.vault.rekey("team-1", { phrase: dave.recoveryPhrase, anchor: aliceTeam.inviteAnchor() });
      const session = await dave.vault.openTeam("team-1");
      expect(session.failure).toBeUndefined();
      expect(session.state).toBe("pending");
    });
  });

  it("an existing member's join with an invite anchor checks it, writes nothing and keeps the floor (D-50)", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    const anchor = aliceTeam.inviteAnchor();
    const floor = (await bundleOf(bob.vault)).floor;
    const commits = bob.store.commits.length;
    await bob.vault.joinTeam("team-1", { anchor });
    bob.store.rollback("team-1", 2);
    await expect(bob.vault.joinTeam("team-1", { anchor })).rejects.toEqual(trust("rollback"));
    expect(bob.store.commits.length).toBe(commits);
    expect((await bundleOf(bob.vault)).floor).toEqual(floor);
  });

  it("a join to a team with no chain is refused at join, before any key is written (D-50)", async () => {
    const { w } = await team();
    const dave = await w.account("dave");
    await expect(dave.vault.joinTeam("team-2")).rejects.toEqual(trust("rollback"));
    expect(await dave.store.list({ type: "member-keys", teamId: "team-2", accountId: "dave" })).toEqual([]);
  });

});

describe("SP-07: anchors written outside the vault can't choose the chain (D-52)", () => {
  /** A version 9 the server forged, owned by mallory and rostering bob's real keys. */
  async function forgedNine(t: Awaited<ReturnType<typeof team>>) {
    const mallory = await t.w.account("mallory");
    await mallory.vault.joinTeam("team-1");
    const m = await bundleOf(mallory.vault);
    const v = await bundleOf(t.members.bob!.vault);
    const entry = (accountId: string, b: typeof m) => ({
      accountId, memberKeysVersion: b.memberKeysVersion, keysHash: keysHash(cc1, b.published), encryptionPublicKey: b.pairs.encryption.publicKey,
    });
    const json = teamKeyVersionToJson(
      createTeamKeyVersion(cc1, {
        teamId: "team-1", version: 9, prevHash: cc1.randomBytes(32),
        owners: [{ accountId: "mallory", signingPublicKey: m.pairs.signing.publicKey }],
        roster: [entry("mallory", m), entry("bob", v)], createdAt: 1,
        signer: { accountId: "mallory", signingPublicKey: m.pairs.signing.publicKey },
        signerSecretKey: m.pairs.signing.secretKey, teamKey: cc1.randomBytes(32), previousKey: cc1.randomBytes(32),
      }),
    );
    return { json, anchor: { version: 9, hash: recordHash(parseTeamKeyVersion(json, { teamId: "team-1" })) } };
  }

  it("a forged local anchor above the floor is refused (review 006 B)", async () => {
    const t = await team("bob");
    const bob = t.members.bob!;
    const forged = await forgedNine(t);
    await bob.localKeys.setAnchor("bob", "team-1", forged.anchor);
    bob.store.fork("team-1", 9, forged.json);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
    // It stays on this device: nothing on the server carries it, so another device of bob opens the real chain (D-66).
    const phone = await t.w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin("1234");
    const session = await phone.vault.openTeam("team-1");
    expect(session.failure).toBeUndefined();
    expect(session.currentVersion).toBe(2);
  });
});
