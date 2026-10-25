/**
 * SP-07: A client never goes back to an older team state, nor below its keys' floor (D-48, D-50).
 * Threats: TH-04, TH-05, TH-46.
 */
import { sessionInternals } from "../../src/team/session.js";
import { describe, expect, it } from "vitest";
import { cc1 } from "../../src/suites/cc1/index.js";
import { createTeamKeyReceiver } from "../../src/team/receiver.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { openBundles } from "../../src/account/member-custody.js";
import { vaultInternals, type Vault } from "../../src/account/vault.js";
import { StoreConflictError } from "../../src/errors.js";
import { createTeamKeyVersion, parseTeamKeyVersion, recordHash, teamKeyVersionToJson } from "../../src/records/team-key-version.js";
import { keysHash } from "../../src/records/member-keys.js";
import { createTeamState, teamStateToJson } from "../../src/records/team-state.js";
import { createMemberKeysWrap, memberKeysWrapToJson } from "../../src/records/member-keys-wrap.js";
import type { TamperingStore } from "../support/fake-store.js";
import { bundleOf, forgeFirstVersion, forgeVersion, versionRecord } from "../support/forge.js";
import { team } from "../support/teams.js";
import { ContentStore, addParts, read } from "../support/content-store.js";

const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });
const stateKey = { type: "team-state", accountId: "bob", teamId: "team-1" } as const;

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

  it("a new device starts from the server's encrypted state, not first-contact trust", async () => {
    const { w } = await threeVersions();
    const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin("1234");
    phone.store.rollback("team-1", 2);
    expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("rollback"));
  });

  it("an older team-state revision doesn't move the client back", async () => {
    const { bob, members } = await threeVersions();
    const old = await bob.store.get(stateKey);
    await (await members.alice!.vault.openTeam("team-1")).owner().rotate({ keep: ["bob"] });
    expect((await bob.vault.openTeam("team-1")).currentVersion).toBe(4);
    bob.store.replace(stateKey, old);
    bob.store.rollback("team-1", 3);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("rollback"));
  });

  it("a corrupted team-state stops keys with no floor, where it is a root (state_unreadable); with a floor it is absent (D-62)", async () => {
    const { bob } = await threeVersions();
    const b64 = (n: number) => Buffer.from(cc1.randomBytes(n)).toString("base64url");
    // Written through the session, as a thief would: each write is the next revision.
    const write = async (wrappedState: Record<string, string>) => {
      const state = (await bob.store.get(stateKey)) as Record<string, unknown> & { revision: number };
      await bob.store.commit([{ op: "compare-and-set", key: stateKey, expectedRevision: state.revision, record: { ...state, revision: state.revision + 1, wrappedState } }]);
    };
    await write({ nonce: b64(24), ciphertext: b64(56) });
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
    await write({ nonce: b64(24), ciphertext: b64(56) });
    // Keys with no floor (written before D-48): the team state is a root, so an unreadable one stops the team.
    const held = await bundleOf(bob.vault);
    const { ports, account } = vaultInternals(bob.vault);
    const context = { accountId: "bob", teamId: "team-1", memberKeysVersion: held.memberKeysVersion, accountKeyVersion: account().version };
    const raw = { signingSeed: held.pairs.signing.secretKey.subarray(0, 32), encryptionSecretKey: held.pairs.encryption.secretKey, teamStateKey: held.pairs.teamStateKey };
    await ports.store.commit([{ op: "replace", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(createMemberKeysWrap(cc1, context, account().key, raw)) }]);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("state_unreadable"));
    // A malformed one fails too there, before any key is tried (D-62).
    await write({ nonce: b64(3), ciphertext: b64(3) });
    await expect(bob.vault.openTeam("team-1")).rejects.toEqual(expect.objectContaining({ code: "MALFORMED_RECORD" }));
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
    const stateOf = (accountId: string) => ({ type: "team-state", accountId, teamId: "team-1" }) as const;

    it("withheld team-state: an existing member's new device refuses a forged team", async () => {
      const { w } = await team("bob");
      const fresh = await w.device("alice");
      await fresh.vault.unlockWithPin("1234");
      fresh.store.drop(stateOf("alice"));
      await forgedTeam(w, fresh, "alice");
      expect((await fresh.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
    });

    it("a team-state a session thief deleted: the new device refuses a forged team", async () => {
      const { members, w } = await team("bob");
      await members.alice!.store.commit([{ op: "delete", key: stateOf("alice") }]);
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
      fresh.store.drop(stateOf("alice"));
      await forgedTeam(w, fresh, "alice");
      const page = { store: fresh.store, anchors: new MemoryLocalKeyStore(), clock: w.clock };
      expect((await receiver.openTeam(page, transfer)).failure).toEqual(trust("rollback"));
    });

    it("a joiner without an invite anchor is protected from its join on: its floor is the chain verified at join (D-50)", async () => {
      const { w } = await team("bob");
      const fresh = await w.device("bob");
      await fresh.vault.unlockWithPin("1234");
      fresh.store.drop(stateOf("bob"));
      await forgedTeam(w, fresh, "bob");
      expect((await fresh.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
    });

    it("an archived team-state below the floor isn't followed (D-50)", async () => {
      const { members, aliceTeam, w } = await team("bob");
      const bob = members.bob!;
      const old = await bob.store.get(stateKey);
      await aliceTeam.owner().rotate({ keep: ["bob"] });
      await (await members.alice!.vault.openTeam("team-1")).owner().rotate({ keep: ["bob"] });
      expect((await bob.vault.openTeam("team-1")).currentVersion).toBe(4);
      await bob.vault.rekey("team-1");
      expect((await bundleOf(bob.vault)).floor?.version).toBe(4);
      const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
      await phone.vault.unlockWithPin("1234");
      phone.store.replace(stateKey, old).rollback("team-1", 3);
      expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("rollback"));
    });

    it("a replayed team-state below the chain, re-read after a write conflict, isn't followed (§6.1 step 7, review 030 D)", async () => {
      const { members, aliceTeam, w } = await team("bob");
      const bob = members.bob!;
      const old = await bob.store.get(stateKey);
      await aliceTeam.owner().rotate({ keep: ["bob"] });
      await (await members.alice!.vault.openTeam("team-1")).owner().rotate({ keep: ["bob"] });
      (await bob.vault.openTeam("team-1")).close();
      expect((await bundleOf(bob.vault)).floor?.version).toBe(4);
      // A new device; the server serves the old revision, readable under bob's keys, below the floor: the write conflicts.
      const phone = await w.device("bob", { localKeys: new MemoryLocalKeyStore() });
      await phone.vault.unlockWithPin("1234");
      phone.store.replace(stateKey, old);
      const session = await phone.vault.openTeam("team-1");
      expect(session.failure).toBeUndefined();
      expect(session.currentVersion).toBe(4);
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

  it("§6.1 step 7: a concurrent team-state written under the older bundle's key is reloaded, not refused", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    await bob.vault.rekey("team-1");
    await aliceTeam.owner().rotate({ keep: ["bob"] });
    const [, older] = await openBundles(vaultInternals(bob.vault).ports, vaultInternals(bob.vault).account(), "team-1");
    const hash = recordHash(await versionRecord(bob.store, "team-1", aliceTeam.currentVersion));
    let injected = false;
    bob.store.onCommit((ops) => {
      if (injected || !ops.some((op) => op.op === "compare-and-set")) return;
      injected = true;
      // Another device, holding only the older bundle, wrote first.
      const record = createTeamState(cc1, { accountId: "bob", teamId: "team-1" }, 9, older!.pairs.teamStateKey, { version: aliceTeam.currentVersion, hash });
      bob.store.replace(stateKey, teamStateToJson(record));
      throw new StoreConflictError();
    });
    expect((await bob.vault.openTeam("team-1")).failure).toBeUndefined();
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

  it("a forged local anchor above the floor is refused, and doesn't spread through team-state (review 006 B)", async () => {
    const t = await team("bob");
    const bob = t.members.bob!;
    const forged = await forgedNine(t);
    await bob.localKeys.setAnchor("bob", "team-1", forged.anchor);
    await bob.store.commit([{ op: "delete", key: stateKey }]);
    bob.store.fork("team-1", 9, forged.json);
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("chain_conflict"));
    expect(await bob.store.get(stateKey)).toBeNull();
  });

  it("a readable team-state whose anchor the chain contradicts is state_conflict; above the chain, rollback; support restores it (review 006 C)", async () => {
    const t = await team("bob");
    const bob = t.members.bob!;
    (await bob.vault.openTeam("team-1")).close();
    const stolen = (await bundleOf(bob.vault)).pairs.teamStateKey; // A9 in a context that holds the team, A7
    const write = async (anchor: { version: number; hash: Uint8Array }) => {
      const json = (await bob.store.get(stateKey)) as { revision: number };
      const record = createTeamState(cc1, { accountId: "bob", teamId: "team-1" }, json.revision + 1, stolen, anchor);
      await bob.store.commit([{ op: "compare-and-set", key: stateKey, expectedRevision: json.revision, record: teamStateToJson(record) }]);
    };
    const phone = await t.w.device("bob", { localKeys: new MemoryLocalKeyStore() });
    await phone.vault.unlockWithPin("1234");
    await write({ version: 2, hash: cc1.randomBytes(32) });
    expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("state_conflict"));
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("state_conflict"));
    t.w.server.restore(stateKey);
    expect((await phone.vault.openTeam("team-1")).failure).toBeUndefined();
    await write({ version: 50, hash: cc1.randomBytes(32) });
    expect((await phone.vault.openTeam("team-1")).failure).toEqual(trust("rollback"));
  });
});

