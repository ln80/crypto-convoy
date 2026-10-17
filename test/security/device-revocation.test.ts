/**
 * SP-10: A revoked device can't unlock the account again.
 * Threats: TH-10.
 */
import { describe, expect, it } from "vitest";
import { world } from "../support/fixtures.js";

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
