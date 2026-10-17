/**
 * SP-07: A client never goes back to an older team state.
 * Threats: TH-05.
 */
import { sessionInternals } from "../../src/team/session.js";
import { describe, expect, it } from "vitest";
import { cc1 } from "../../src/suites/cc1/index.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { bundleOf, forgeVersion } from "../support/forge.js";
import { team } from "../support/teams.js";
import { ContentStore, addParts, read } from "../support/content-store.js";

const trust = (reason: string) => expect.objectContaining({ code: "TRUST_FAILURE", reason });
const stateKey = { type: "team-state", accountId: "bob", teamId: "team-1" } as const;

async function threeVersions() {
  const t = await team("bob");
  await t.aliceTeam.rotate({ keep: ["bob"] });
  await (await t.members.alice!.vault.openTeam("team-1")).rotate({ keep: ["bob"] });
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
    await addParts(t.aliceTeam.beginItem(), content, "old", ["from version 1"]).seal("old");
    await t.aliceTeam.rotate({ keep: ["bob"] });
    await (await t.members.alice!.vault.openTeam("team-1")).rotate({ keep: ["bob"] });
    const bob = t.members.bob!;
    expect((await bob.vault.openTeam("team-1")).currentVersion).toBe(3);

    const session = await bob.vault.openTeam("team-1");
    expect(read(await (await session.openItem("old")).part(0, content.get("old", 0)))).toBe("from version 1");

    // A server that swaps a record below the anchor is caught by the hash link.
    const alice = await bundleOf(t.members.alice!.vault);
    bob.store.fork("team-1", 2, await forgeVersion(bob.store, { version: 2, owners: [{ accountId: "alice", keys: alice.pairs }], signer: { accountId: "alice", keys: alice.pairs } }));
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
    bob.store.fork("team-1", 3, await forgeVersion(bob.store, { version: 3, owners: [{ accountId: "alice", keys: alice.pairs }], signer: { accountId: "alice", keys: alice.pairs } }));
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
    await (await members.alice!.vault.openTeam("team-1")).rotate({ keep: ["bob"] });
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
    await aliceTeam.rotate({ keep: [] });
    const anchor = aliceTeam.inviteAnchor();
    const dave = await w.account("dave");
    dave.store.rollback("team-1", 1);
    await dave.vault.joinTeam("team-1");
    expect((await dave.vault.openTeam("team-1", { anchor })).failure).toEqual(trust("rollback"));
    const erin = await w.account("erin");
    await erin.vault.joinTeam("team-1");
    expect((await erin.vault.openTeam("team-1", { anchor })).state).toBe("pending");
  });
});
