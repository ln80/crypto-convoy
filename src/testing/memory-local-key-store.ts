import type { LocalAnchor, LocalDevice, LocalKeyStore } from "../ports.js";

/** `LocalKeyStore` in memory: one device's state, lost when the object is dropped. */
export class MemoryLocalKeyStore implements LocalKeyStore {
  readonly #devices = new Map<string, LocalDevice>();
  readonly #versions = new Map<string, number>();
  readonly #anchors = new Map<string, LocalAnchor>();

  async getDevice(accountId: string) {
    const device = this.#devices.get(accountId);
    return device ? { deviceId: device.deviceId, deviceKey: device.deviceKey.slice() } : null;
  }
  async setDevice(accountId: string, device: LocalDevice) {
    this.#devices.set(accountId, { deviceId: device.deviceId, deviceKey: device.deviceKey.slice() });
  }
  async deleteDevice(accountId: string) {
    this.#devices.delete(accountId);
  }
  async getAccountKeyVersion(accountId: string) {
    return this.#versions.get(accountId) ?? null;
  }
  async setAccountKeyVersion(accountId: string, version: number) {
    this.#versions.set(accountId, version);
  }
  async getAnchor(accountId: string, teamId: string) {
    const anchor = this.#anchors.get(`${accountId}\0${teamId}`);
    return anchor ? { version: anchor.version, hash: anchor.hash.slice() } : null;
  }
  async setAnchor(accountId: string, teamId: string, anchor: LocalAnchor) {
    this.#anchors.set(`${accountId}\0${teamId}`, { version: anchor.version, hash: anchor.hash.slice() });
  }
  async deleteAnchor(accountId: string, teamId: string) {
    this.#anchors.delete(`${accountId}\0${teamId}`);
  }
}
