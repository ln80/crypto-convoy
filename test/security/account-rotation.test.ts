/**
 * SP-11: The account key can be rotated.
 * SP-25: An open vault alone can't change the account's credentials (rotation needs the phrase).
 * SP-07: the member keys' anchor floor survives rotations and re-keys (D-48).
 * Threats: TH-04, TH-10, TH-12, TH-20, TH-45.
 */
import { describe, expect, it } from "vitest";
import { openAccountKeyWrap, parseAccountKeyWrap } from "../../src/records/account-key-wrap.js";
import { world } from "../support/fixtures.js";
import { bundleOf } from "../support/forge.js";
import { accessOf } from "../support/forge.js";
import { team } from "../support/teams.js";

const code = (c: string) => expect.objectContaining({ code: c });

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

  it("SP-07: the keys' anchor floor survives a rotation and a re-key (D-48)", async () => {
    const { members } = await team("bob");
    const alice = members.alice!;
    const floor = (await bundleOf(alice.vault)).floor!;
    expect(floor.version).toBe(1);
    await alice.vault.rotate({ phrase: alice.recoveryPhrase });
    expect((await bundleOf(alice.vault)).floor).toEqual(floor);
    await alice.vault.rekey("team-1", { phrase: alice.recoveryPhrase });
    expect((await bundleOf(alice.vault)).floor).toEqual(floor);
  });

  it("SP-07: a member who joined without an invite anchor gets a floor at its first re-key (D-48)", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    expect((await bundleOf(bob.vault)).floor).toBeUndefined();
    await bob.vault.rekey("team-1");
    // Bob's first open anchored him at version 1; his local anchor is the floor.
    expect((await bundleOf(bob.vault)).floor?.version).toBe(1);
    expect(aliceTeam.currentVersion).toBe(2);
  });
});
