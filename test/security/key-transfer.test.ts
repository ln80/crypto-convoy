/**
 * SP-02: A team session only holds its own team's keys, also across contexts.
 * Threats: TH-19, TH-39.
 */
import { describe, expect, it } from "vitest";
import { vaultInternals } from "../../src/account/vault.js";
import { fromBase64url, toBase64url } from "../../src/encoding/base64url.js";
import { createTeamKeyReceiver } from "../../src/team/receiver.js";
import { MemoryLocalKeyStore } from "../../src/testing/index.js";
import { ContentStore, addParts, read } from "../support/content-store.js";
import { TamperingStore } from "../support/fake-store.js";
import { forgeMemberKeys, strangerKeys } from "../support/forge.js";
import { team } from "../support/teams.js";

const failed = expect.objectContaining({ code: "DECRYPTION_FAILED" });

async function setup() {
  const t = await team("bob");
  await t.members.alice!.vault.createTeam("team-2");
  const alice = t.members.alice!;
  // The page: its own key store view and its own local storage, no vault.
  const page = { store: t.w.server.as("alice"), anchors: new MemoryLocalKeyStore(), clock: t.w.clock };
  return { ...t, alice, page };
}

describe("SP-02: a team's keys reach only the receiver that asked, for that team", () => {
  it("a split vault and page: the page works with the team, without the account key", async () => {
    const { alice, aliceTeam, page } = await setup();
    const content = new ContentStore();
    await addParts(aliceTeam.beginItem(), content, "item-1", ["from the vault context"]).seal("item-1");

    const receiver = await createTeamKeyReceiver("alice", "team-1");
    const transfer = await alice.vault.exportTeamKeys("team-1", receiver.request);
    const session = await receiver.openTeam(page, transfer);
    expect(session.state).toBe("ready");
    expect(read(await (await session.openItem("item-1")).part(0, content.get("item-1", 0)))).toBe("from the vault context");

    const accountKey = Buffer.from(vaultInternals(alice.vault).account().key);
    expect(Buffer.from(fromBase64url(transfer.slice(1))).includes(accountKey)).toBe(false);
    expect(JSON.stringify(session)).not.toContain(accountKey.toString("base64url"));
  });

  it("another receiver can't open a transfer, and a receiver opens only once", async () => {
    const { alice, page } = await setup();
    const receiver = await createTeamKeyReceiver("alice", "team-1");
    const other = await createTeamKeyReceiver("alice", "team-1");
    const transfer = await alice.vault.exportTeamKeys("team-1", receiver.request);
    await expect(other.openTeam(page, transfer)).rejects.toEqual(failed);
    await receiver.openTeam(page, transfer);
    await expect(receiver.openTeam(page, transfer)).rejects.toEqual(failed);
  });

  it("a transfer of another team, or for another account, is refused", async () => {
    const { alice, page } = await setup();
    const wantsTeam1 = await createTeamKeyReceiver("alice", "team-1");
    await expect(wantsTeam1.openTeam(page, await alice.vault.exportTeamKeys("team-2", wantsTeam1.request))).rejects.toEqual(failed);
    const wantsBob = await createTeamKeyReceiver("bob", "team-1");
    await expect(wantsBob.openTeam(page, await alice.vault.exportTeamKeys("team-1", wantsBob.request))).rejects.toEqual(failed);
  });

  it("a tampered transfer is refused", async () => {
    const { alice, page } = await setup();
    const receiver = await createTeamKeyReceiver("alice", "team-1");
    const bytes = fromBase64url((await alice.vault.exportTeamKeys("team-1", receiver.request)).slice(1));
    bytes[bytes.length - 1]! ^= 1;
    await expect(receiver.openTeam(page, "1" + toBase64url(bytes))).rejects.toEqual(failed);
  });

  it("bundles that don't match the published keys give an unverified session", async () => {
    const { alice, page, w } = await setup();
    const receiver = await createTeamKeyReceiver("alice", "team-1");
    const transfer = await alice.vault.exportTeamKeys("team-1", receiver.request);
    const store = new TamperingStore(w.server.as("alice")).replace({ type: "member-keys", accountId: "alice" }, forgeMemberKeys("alice", 1, strangerKeys()));
    const session = await receiver.openTeam({ ...page, store }, transfer);
    expect(session.state).toBe("unverified");
    expect(session.failure).toEqual(expect.objectContaining({ reason: "key_mismatch" }));
  });

  it("the vault refuses a malformed or low-order request", async () => {
    const { alice } = await setup();
    await expect(alice.vault.exportTeamKeys("team-1", "1" + toBase64url(new Uint8Array(32)))).rejects.toEqual(expect.objectContaining({ code: "MALFORMED_RECORD" }));
    await expect(alice.vault.exportTeamKeys("team-1", "2abc")).rejects.toEqual(expect.objectContaining({ code: "UNSUPPORTED_VERSION" }));
  });

  it("Limit: the vault exports to whoever the integration lets ask", async () => {
    const { alice, page } = await setup();
    const anyone = await createTeamKeyReceiver("alice", "team-1");
    expect((await anyone.openTeam(page, await alice.vault.exportTeamKeys("team-1", anyone.request))).state).toBe("ready");
  });
});
