/**
 * SP-10: A revoked device can't unlock the account again.
 * Threats: TH-10.
 */
import { describe, expect, it } from "vitest";
import { world } from "../support/fixtures.js";
import { openGrant, parseGrant } from "../../src/records/grant.js";
import { bundleOf } from "../support/forge.js";
import { team } from "../support/teams.js";

const code = (c: string) => expect.objectContaining({ code: c });

describe("SP-10: a revoked device can't unlock again", () => {
  it("refuses the device key once its wrap is deleted", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const phone = await w.device("alice");
    await phone.vault.unlockWithPin("1234");
    const phoneId = (await phone.localKeys.getDevice("alice"))!.deviceId;
    expect(await laptop.vault.listDevices()).toContain(phoneId);
    expect(await laptop.vault.listDevices()).toHaveLength(2);

    await laptop.vault.revokeDevice(phoneId);
    phone.vault.lock();
    await expect(phone.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    expect(await laptop.vault.listDevices()).toHaveLength(1);
  });

  it("revoking the current device forgets its local key", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const [id] = await laptop.vault.listDevices();
    await laptop.vault.revokeDevice(id!);
    expect(await laptop.localKeys.getDevice("alice")).toBeNull();
  });

  it("the device registers again with the PIN", async () => {
    const w = world();
    const laptop = await w.account("alice");
    const [id] = await laptop.vault.listDevices();
    await laptop.vault.revokeDevice(id!);
    laptop.vault.lock();
    await expect(laptop.vault.unlock()).rejects.toEqual(code("DEVICE_NOT_REGISTERED"));
    await laptop.vault.unlockWithPin("1234");
    laptop.vault.lock();
    await laptop.vault.unlock();
  });
});

describe("SP-10 Limit: revocation alone doesn't evict copied keys; the full remedy does", () => {
  it("revoke, rotate the account key, re-key and rotate the team: copied keys open nothing new", async () => {
    const { members, aliceTeam } = await team("bob");
    const bob = members.bob!;
    const stolenAccountKey = bob.vault.requireAccount().key.slice();
    const stolenBundle = await bundleOf(bob.vault);

    // Revocation alone: the copied member keys still open a version granted afterwards.
    await aliceTeam.rotate({ keep: ["bob"] });
    const v2 = parseGrant((await bob.store.list({ type: "grant", teamId: "team-1", accountId: "bob", teamKeyVersion: 2 }))[0], { teamId: "team-1" });
    expect(openGrant(v2, stolenBundle.pairs.encryption)).toHaveLength(32);

    // The full remedy (D-21).
    await bob.vault.rotate({ pin: bob.pin, phrase: bob.recoveryPhrase });
    await bob.vault.rekey("team-1");
    await aliceTeam.rotate({ keep: ["bob"], approveRekeys: ["bob"] });

    const v3 = parseGrant((await bob.store.list({ type: "grant", teamId: "team-1", accountId: "bob", teamKeyVersion: 3 }))[0], { teamId: "team-1" });
    expect(() => openGrant(v3, stolenBundle.pairs.encryption)).toThrow(code("DECRYPTION_FAILED"));
    const wraps = await bob.store.list({ type: "member-keys-wrap", accountId: "bob", accountKeyVersion: 2 });
    expect(wraps.length).toBeGreaterThan(0);
    expect(Buffer.from(stolenAccountKey).equals(Buffer.from(bob.vault.requireAccount().key))).toBe(false);
    expect((await bob.vault.openTeam("team-1")).state).toBe("ready");
  });
});
