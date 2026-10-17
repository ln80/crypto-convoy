// The account vault (§5, D-03): the only holder of the account key.
import { ConvoyError } from "../errors.js";
import {
  callPort,
  resolveSettings,
  systemClock,
  type Clock,
  type LocalDevice,
  type LocalKeyStore,
  type OprfService,
  type RecordStore,
  type Settings,
  type WriteOp,
} from "../ports.js";
import { openAccountKeyWrap, parseAccountKeyWrap } from "../records/account-key-wrap.js";
import { CURRENT_SUITE, ready } from "../suites/registry.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { createWrap, replaceWrap, wrapKey } from "./context.js";
import { deriveRecoveryKey } from "./recovery-key.js";
import { rotateAccount } from "./rotation.js";
import {
  acceptVersion,
  commit,
  currentVersion,
  fetchWrap,
  newDevice,
  openWithPin,
  pinWrap,
  recoveryWrap,
} from "./unlock-methods.js";

export interface VaultOptions {
  readonly store: RecordStore;
  readonly oprf: OprfService;
  readonly localKeys: LocalKeyStore;
  readonly clock?: Clock;
  readonly settings?: Settings;
}

/** Opens an account's vault. Loads libsodium; throws `MALFORMED_RECORD` for settings below the floor. */
export async function createVault(options: VaultOptions, accountId: string): Promise<Vault> {
  await ready();
  const ports: AccountPorts = {
    suite: CURRENT_SUITE,
    store: options.store,
    oprf: options.oprf,
    localKeys: options.localKeys,
    clock: options.clock ?? systemClock,
    settings: resolveSettings(options.settings),
  };
  return new Vault(ports, accountId);
}

/**
 * Holds the account key once unlocked. Methods that need it throw a plain `Error`
 * when the vault is locked: that is a programming error, not a protocol failure.
 */
export class Vault {
  readonly #ports: AccountPorts;
  readonly accountId: string;
  #account: OpenAccount | null = null;

  /** @internal Use `createVault`. */
  constructor(ports: AccountPorts, accountId: string) {
    this.#ports = ports;
    this.accountId = accountId;
  }

  get isUnlocked(): boolean {
    return this.#account !== null;
  }

  /** @internal For the team operations of this package. */
  get ports(): AccountPorts {
    return this.#ports;
  }

  /** @internal */
  requireAccount(): OpenAccount {
    if (!this.#account) throw new Error("crypto-convoy: the vault is locked");
    return this.#account;
  }

  /** Forgets the account key (best-effort wipe). */
  lock(): void {
    if (this.#account) this.#ports.suite.wipe(this.#account.key);
    this.#account = null;
  }

  /**
   * Creates the account (§5.3) and registers this device. Returns the recovery phrase,
   * to show once. Throws `PIN_RATE_LIMITED`, `STALE_VERSION` (account exists), `STORE_ERROR`.
   */
  async setup(pin: string): Promise<{ recoveryPhrase: string }> {
    const { suite, localKeys } = this.#ports;
    const account: OpenAccount = { accountId: this.accountId, version: 1, key: suite.randomBytes(suite.sizes.key) };
    const recoveryPhrase = suite.generateRecoveryPhrase();
    const { device, op } = newDevice(this.#ports, account);
    await commit(this.#ports, [
      createWrap(await pinWrap(this.#ports, account, pin)),
      createWrap(recoveryWrap(this.#ports, account, recoveryPhrase)),
      op,
      { op: "set-account-key-version", accountId: this.accountId, expected: null, accountKeyVersion: 1 },
    ]);
    await callPort(() => localKeys.setDevice(this.accountId, device));
    await acceptVersion(this.#ports, account);
    this.#account = account;
    return { recoveryPhrase };
  }

  /** Unlocks with this device's key (§5.4). Throws `DEVICE_NOT_REGISTERED`, `TRUST_FAILURE` (`rollback`). */
  async unlock(): Promise<void> {
    const { localKeys } = this.#ports;
    const device = await callPort(() => localKeys.getDevice(this.accountId));
    if (!device) throw new ConvoyError("DEVICE_NOT_REGISTERED");
    const version = await currentVersion(this.#ports, this.accountId);
    if (version === null) throw new ConvoyError("DEVICE_NOT_REGISTERED");
    const wrap = await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "device", deviceId: device.deviceId });
    if (!wrap) throw new ConvoyError("DEVICE_NOT_REGISTERED");
    await this.#open({ accountId: this.accountId, version, key: openAccountKeyWrap(wrap, device.deviceKey) });
  }

  /**
   * Unlocks with the PIN (§5.4), registers this device if needed, and upgrades an
   * outdated PIN wrap. Throws `WRONG_CREDENTIAL`, `PIN_RATE_LIMITED`, `MALFORMED_RECORD`.
   */
  async unlockWithPin(pin: string): Promise<void> {
    const version = await this.#requireVersion();
    const wrap = await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "pin" });
    if (!wrap) throw new ConvoyError("STORE_ERROR");
    const account = { accountId: this.accountId, version, key: await openWithPin(this.#ports, wrap, pin, "unlock") };

    const { ops, device } = await this.#registration(account);
    const { write } = this.#ports.settings.argon2;
    const currentKeyId = await callPort(() => this.#ports.oprf.currentKeyId(this.accountId));
    const kdf = wrap.kdf!;
    if (kdf.opslimit < write.opslimit || kdf.memlimit < write.memlimit || kdf.oprfKeyId !== currentKeyId) {
      ops.push(...replaceWrap(await pinWrap(this.#ports, account, pin)));
    }
    if (ops.length > 0) await commit(this.#ports, ops);
    await this.#keepDevice(device);
    await this.#open(account);
  }

  /**
   * Unlocks with the recovery phrase and registers this device, then sets a new PIN (§5.4).
   * If only the new PIN fails (`PIN_RATE_LIMITED`), the vault stays unlocked: call `changePin` later.
   */
  async recover(phrase: string, newPin: string): Promise<void> {
    const { suite } = this.#ports;
    const version = await this.#requireVersion();
    const wrap = await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "recovery" });
    if (!wrap) throw new ConvoyError("STORE_ERROR");
    const recoveryKey = deriveRecoveryKey(suite, this.accountId, phrase);
    let key: Uint8Array;
    try {
      key = openAccountKeyWrap(wrap, recoveryKey);
    } finally {
      suite.wipe(recoveryKey);
    }
    const account = { accountId: this.accountId, version, key };
    const { ops, device } = await this.#registration(account);
    if (ops.length > 0) await commit(this.#ports, ops);
    await this.#keepDevice(device);
    await this.#open(account);
    await this.changePin(newPin);
  }

  /** Replaces the PIN wrap (§5.6). Throws `PIN_RATE_LIMITED`, `STALE_VERSION`. */
  async changePin(newPin: string): Promise<void> {
    const account = this.requireAccount();
    await commit(this.#ports, replaceWrap(await pinWrap(this.#ports, account, newPin)));
  }

  /** Replaces the recovery phrase (§5.6) and returns the new one, to show once. */
  async replaceRecoveryPhrase(): Promise<{ recoveryPhrase: string }> {
    const account = this.requireAccount();
    const recoveryPhrase = this.#ports.suite.generateRecoveryPhrase();
    await commit(this.#ports, replaceWrap(recoveryWrap(this.#ports, account, recoveryPhrase)));
    return { recoveryPhrase };
  }

  /** The `deviceId` of every device wrap at the current version (§5.5). */
  async listDevices(): Promise<string[]> {
    const account = this.requireAccount();
    const wraps = await callPort(() =>
      this.#ports.store.list({ type: "account-key-wrap", accountId: this.accountId, accountKeyVersion: account.version }),
    );
    const expected = { accountId: this.accountId, accountKeyVersion: account.version };
    return wraps
      .filter((json) => (json as { method?: unknown }).method === "device")
      .map((json) => parseAccountKeyWrap(json, { ...expected, method: "device" }).deviceId!);
  }

  /** Deletes a device's wrap: it can't unlock again (§5.5, SP-10). */
  async revokeDevice(deviceId: string): Promise<void> {
    const account = this.requireAccount();
    await commit(this.#ports, [{ op: "delete", key: wrapKey({ accountId: this.accountId, accountKeyVersion: account.version, method: "device", deviceId }) }]);
    const local = await callPort(() => this.#ports.localKeys.getDevice(this.accountId));
    if (local?.deviceId === deviceId) await callPort(() => this.#ports.localKeys.deleteDevice(this.accountId));
  }

  /**
   * Rotates the account key (§5.7). Pass the current `phrase` to keep it, or omit it to get a
   * new one. Other devices must register again. Throws `WRONG_CREDENTIAL`, `PIN_RATE_LIMITED`, `STALE_VERSION`.
   */
  async rotate(input: { pin: string; phrase?: string }): Promise<{ recoveryPhrase?: string }> {
    const current = this.requireAccount();
    const { account, recoveryPhrase } = await rotateAccount(this.#ports, current, input);
    this.lock();
    this.#account = account;
    return recoveryPhrase ? { recoveryPhrase } : {};
  }

  /** Registers this device unless it has a live wrap at the account's version (§5.5). */
  async #registration(account: OpenAccount): Promise<{ ops: WriteOp[]; device: LocalDevice | null }> {
    const local = await callPort(() => this.#ports.localKeys.getDevice(this.accountId));
    if (local) {
      const expected = { accountId: this.accountId, accountKeyVersion: account.version, method: "device", deviceId: local.deviceId } as const;
      if (await fetchWrap(this.#ports, expected)) return { ops: [], device: null };
    }
    const { device, op } = newDevice(this.#ports, account);
    return { ops: [op], device };
  }

  /** Kept only once its wrap is stored. */
  async #keepDevice(device: LocalDevice | null) {
    if (device) await callPort(() => this.#ports.localKeys.setDevice(this.accountId, device));
  }

  async #requireVersion(): Promise<number> {
    const version = await currentVersion(this.#ports, this.accountId);
    if (version === null) throw new ConvoyError("STORE_ERROR");
    return version;
  }

  async #open(account: OpenAccount) {
    await acceptVersion(this.#ports, account);
    this.lock();
    this.#account = account;
  }
}
