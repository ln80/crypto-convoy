/**
 * SP-07: A client never goes back to an older team state.
 * Threats: TH-05.
 */
import { sessionInternals } from "../../src/team/session.js";
import { describe, expect, it } from "vitest";
import { cc1 } from "../../src/suites/cc1/index.js";
import { createTeamKeyReceiver } from "../../src/team/receiver.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { bundleOf, forgeVersion } from "../support/forge.js";
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

  it("refuses a corrupted team-state as state_unreadable, never ignoring it", async () => {
    const { bob } = await threeVersions();
    const state = (await bob.store.get(stateKey)) as Record<string, unknown>;
    const b64 = (n: number) => Buffer.from(cc1.randomBytes(n)).toString("base64url");
    bob.store.replace(stateKey, { ...state, wrappedState: { nonce: b64(24), ciphertext: b64(56) } });
    expect((await bob.vault.openTeam("team-1")).failure).toEqual(trust("state_unreadable"));
  });

  it("a joining member refuses a chain that doesn't contain the invite anchor", async () => {
    const { aliceTeam, w } = await team();
    await aliceTeam.owner().rotate({ keep: [] });
    const anchor = aliceTeam.inviteAnchor();
    const dave = await w.account("dave");
    dave.store.rollback("team-1", 1);
    await dave.vault.joinTeam("team-1");
    expect((await dave.vault.openTeam("team-1", { anchor })).failure).toEqual(trust("rollback"));
    const erin = await w.account("erin");
    await erin.vault.joinTeam("team-1");
    expect((await erin.vault.openTeam("team-1", { anchor })).state).toBe("pending");
  });

  it("a joining member's receiving context refuses a chain that doesn't contain the invite anchor (§3.8)", async () => {
    const { aliceTeam, w } = await team();
    await aliceTeam.owner().rotate({ keep: [] });
    const anchor = aliceTeam.inviteAnchor();
    /** A joiner whose team opens in another context (D-29), e.g. a page beside a vault frame. */
    const joinInPage = async (name: string, { rollback, withAnchor }: { rollback: boolean; withAnchor: boolean }) => {
      const member = await w.account(name);
      if (rollback) member.store.rollback("team-1", 1);
      await member.vault.joinTeam("team-1");
      const receiver = await createTeamKeyReceiver(name, "team-1");
      const transfer = await member.vault.exportTeamKeys("team-1", receiver.request);
      const page = { store: member.store, anchors: new MemoryLocalKeyStore(), clock: w.clock };
      return receiver.openTeam(page, transfer, withAnchor ? { anchor } : {});
    };
    expect((await joinInPage("dave", { rollback: true, withAnchor: true })).failure).toEqual(trust("rollback"));
    expect((await joinInPage("erin", { rollback: false, withAnchor: true })).state).toBe("pending");
    // Without the anchor, first contact trusts what the server serves (TH-04): the same cut chain opens.
    expect((await joinInPage("frank", { rollback: true, withAnchor: false })).state).toBe("pending");
  });
});
