// The account vault (§5, D-03): the only holder of the account key.
import { decodeAnchor } from "../encoding/link.js";
import { ConvoyError, trustFailure } from "../errors.js";
import {
  callPort,
  resolveSettings,
  systemClock,
  type Clock,
  type AnchorStore,
  type DeviceKeyStore,
  type LocalDevice,
  type OprfService,
  type RecordStore,
  type Settings,
  type WriteOp,
} from "../ports.js";
import { openAccountKeyWrap, openRecoveryPublicKey, parseAccountKeyWrap } from "../records/account-key-wrap.js";
import { CURRENT_SUITE, ready } from "../suites/registry.js";
import type { TeamSession } from "../team/session.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { createWrap, replaceWrap, wrapKey } from "./context.js";
import { deriveRecoveryKeys } from "./recovery-key.js";
import {
  accountTeams,
  currentRecoveryKey,
  recoverySigner,
  rekeyTeam,
  rekeyTeams,
  samePhrase,
  teamsWithForeignKeys,
  teamsWithOldRecoveryKey,
  type RekeyReport,
} from "./recovery.js";
import { rotateAccount } from "./rotation.js";
import { verifiedChain } from "../team/load.js";
import { currentOwners, exportBundles, newMemberKeys, newTeamOps, nextMemberKeysVersion, openBundles, openSession } from "./member-custody.js";
import {
  acceptVersion,
  commit,
  currentVersion,
  fetchWrap,
  newDevice,
  openWithPin,
  pinWrap,
  recoveryPublicKey,
  recoveryWrap,
  verifyPhrase,
  verifyPin,
} from "./unlock-methods.js";

export interface VaultOptions {
  readonly store: RecordStore;
  readonly oprf: OprfService;
  /** The vault's half of local storage: device key, account key version. */
  readonly deviceKeys: DeviceKeyStore;
  /** Only to open team sessions in the vault's own context (`openTeam`). */
  readonly anchors?: AnchorStore;
  readonly clock?: Clock;
  readonly settings?: Settings;
}

export interface VaultStatus {
  readonly account: "not-set-up" | "locked" | "unlocked";
  readonly deviceRegistered: boolean;
  /** This device's id, or `null` when it holds none: the key for the integration's device labels (§5.5). */
  readonly deviceId: string | null;
  /** Recovery is set up when a recovery wrap exists at the current account key version (D-35). */
  readonly recovery: "not-set-up" | "set-up";
  /** No PIN after a rotation with the phrase alone, until `changePin` sets one (D-40). */
  readonly pin: "not-set-up" | "set-up";
}

/** One registered device of the account (§5.5). */
export interface DeviceEntry {
  readonly deviceId: string;
  /** This device. */
  readonly current: boolean;
}

/** Something about the account the user should act on, with the operation that clears it (§12). */
export interface VaultWarning {
  readonly code: "recovery-not-set-up" | "pin-not-set-up" | "rekey-needed" | "foreign-member-keys";
  /**
   * For `rekey-needed`: teams whose member keys don't carry the current recovery key. For
   * `foreign-member-keys`: teams with keys published under the account that this vault didn't make
   * (D-43): someone may hold the session; end other sessions, then re-key.
   */
  readonly teamIds: readonly string[];
  readonly action: "beginRecoverySetup" | "changePin" | "rekey";
}

export type { RekeyReport };

/** Opens an account's vault. Loads libsodium; throws `MALFORMED_RECORD` for settings below the floor. */
export async function createVault(options: VaultOptions, accountId: string): Promise<Vault> {
  await ready();
  const ports: AccountPorts = {
    suite: CURRENT_SUITE,
    store: options.store,
    oprf: options.oprf,
    deviceKeys: options.deviceKeys,
    ...(options.anchors ? { anchors: options.anchors } : {}),
    clock: options.clock ?? systemClock,
    settings: resolveSettings(options.settings),
  };
  return new Vault(ports, accountId);
}

/** Library-only access to the vault's ports and open account key. Never exported from the package entry (D-15). */
export interface VaultInternals {
  readonly ports: AccountPorts;
  account(): OpenAccount;
}

const VAULT_INTERNALS = new WeakMap<Vault, VaultInternals>();

export function vaultInternals(vault: Vault): VaultInternals {
  return VAULT_INTERNALS.get(vault)!;
}

/**
 * Holds the account key once unlocked. Methods that need it throw a plain `Error`
 * when the vault is locked: that is a programming error, not a protocol failure.
 */
export class Vault {
  readonly #ports: AccountPorts;
  readonly accountId: string;
  #account: OpenAccount | null = null;
  /** A phrase shown to the user and not yet confirmed (§5.10). Memory only. */
  #pendingPhrase: string | null = null;

  /** @internal Use `createVault`. */
  constructor(ports: AccountPorts, accountId: string) {
    this.#ports = ports;
    this.accountId = accountId;
    VAULT_INTERNALS.set(this, { ports, account: () => this.#requireAccount() });
  }

  get isUnlocked(): boolean {
    return this.#account !== null;
  }

  #requireAccount(): OpenAccount {
    if (!this.#account) throw new Error("crypto-convoy: the vault is locked");
    return this.#account;
  }

  /** Forgets the account key (best-effort wipe). */
  lock(): void {
    if (this.#account) this.#ports.suite.wipe(this.#account.key);
    this.#account = null;
    this.#pendingPhrase = null;
  }

  /**
   * Creates the account (§5.3) and registers this device. Set up recovery next
   * (`beginRecoverySetup`): teams need it. Throws `PIN_RATE_LIMITED`, `STALE_VERSION` (account exists), `STORE_ERROR`.
   */
  async setup(pin: string): Promise<void> {
    const { suite, deviceKeys } = this.#ports;
    const account: OpenAccount = { accountId: this.accountId, version: 1, key: suite.randomBytes(suite.sizes.key) };
    const { device, op } = newDevice(this.#ports, account);
    await commit(this.#ports, [
      createWrap(await pinWrap(this.#ports, account, pin)),
      op,
      { op: "set-account-key-version", accountId: this.accountId, expected: null, accountKeyVersion: 1 },
    ]);
    await callPort(() => deviceKeys.setDevice(this.accountId, device));
    await acceptVersion(this.#ports, account);
    this.#account = account;
  }

  /**
   * A new recovery phrase to show the user (§5.10). Nothing is stored until the user types it
   * back with `confirmRecoveryPhrase`; beginning again replaces it.
   */
  beginRecoverySetup(): { recoveryPhrase: string } {
    this.#requireAccount();
    this.#pendingPhrase = this.#ports.suite.generateRecoveryPhrase();
    return { recoveryPhrase: this.#pendingPhrase };
  }

  /**
   * Stores the recovery wrap for the phrase the user typed back (§5.10). Replacing a phrase needs
   * the current phrase or the current PIN (§5.6, D-41), and re-keys every team with the new
   * recovery key: proven with `currentPhrase`, a human approval with `currentPin`. A first setup
   * needs neither. Throws `WRONG_CREDENTIAL` (not the phrase shown, or not a current credential),
   * `MALFORMED_RECORD` (a replacement with neither), `PIN_RATE_LIMITED`, `STALE_VERSION`.
   */
  async confirmRecoveryPhrase(phrase: string, options: { currentPhrase?: string; currentPin?: string } = {}): Promise<RekeyReport> {
    const account = this.#requireAccount();
    const pending = this.#pendingPhrase;
    if (pending === null || !samePhrase(phrase, pending)) throw new ConvoyError("WRONG_CREDENTIAL");
    const old = await currentRecoveryKey(this.#ports, account);
    const { currentPhrase, currentPin } = options ?? {};
    if (old && typeof currentPhrase !== "string") {
      if (typeof currentPin !== "string") throw new ConvoyError("MALFORMED_RECORD");
      await verifyPin(this.#ports, account, currentPin);
    }
    // The current phrase's signing key must be the one the recovery wrap names: that checks it.
    const signer = old && typeof currentPhrase === "string" ? recoverySigner(this.#ports, this.accountId, currentPhrase, old) : undefined;
    try {
      const wrap = recoveryWrap(this.#ports, account, pending);
      await commit(this.#ports, old ? replaceWrap(wrap) : [createWrap(wrap)]);
      this.#pendingPhrase = null;
      const next = openRecoveryPublicKey(wrap, account.key);
      return await rekeyTeams(this.#ports, account, await teamsWithOldRecoveryKey(this.#ports, account, next), next, signer);
    } finally {
      if (signer) this.#ports.suite.wipe(signer.secretKey);
    }
  }

  /** Unlocks with this device's key (§5.4). Throws `DEVICE_NOT_REGISTERED`, `TRUST_FAILURE` (`rollback`). */
  async unlock(): Promise<void> {
    const device = await callPort(() => this.#ports.deviceKeys.getDevice(this.accountId));
    if (!device) throw new ConvoyError("DEVICE_NOT_REGISTERED");
    const version = await currentVersion(this.#ports, this.accountId);
    if (version === null) throw new ConvoyError("DEVICE_NOT_REGISTERED");
    const wrap = await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "device", deviceId: device.deviceId });
    if (!wrap) throw new ConvoyError("DEVICE_NOT_REGISTERED");
    await this.#open({ accountId: this.accountId, version, key: openAccountKeyWrap(wrap, device.deviceKey) });
  }

  /**
   * Unlocks with the PIN (§5.4), registers this device if needed, and upgrades an
   * outdated PIN wrap. Throws `WRONG_CREDENTIAL`, `PIN_RATE_LIMITED`, `PIN_NOT_SET_UP` (no PIN, D-40),
   * `MALFORMED_RECORD`.
   */
  async unlockWithPin(pin: string): Promise<void> {
    const version = await this.#requireVersion();
    const wrap = await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "pin" });
    // Rotated with the phrase alone (D-40): no PIN until one is set, and no evaluation spent.
    if (!wrap) throw new ConvoyError("PIN_NOT_SET_UP");
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
    const { recoveryKey, signing } = deriveRecoveryKeys(suite, this.accountId, phrase);
    let key: Uint8Array;
    try {
      key = openAccountKeyWrap(wrap, recoveryKey);
      // The recovery key the wrap names must be this phrase's (§4.1).
      if (!suite.equal(openRecoveryPublicKey(wrap, key), signing.publicKey)) throw trustFailure("key_mismatch");
    } finally {
      suite.wipe(recoveryKey, signing.secretKey);
    }
    const account = { accountId: this.accountId, version, key };
    const { ops, device } = await this.#registration(account);
    if (ops.length > 0) await commit(this.#ports, ops);
    await this.#keepDevice(device);
    await this.#open(account);
    await this.changePin(newPin, { phrase });
  }

  /**
   * Sets the PIN (§5.6): replaces the PIN wrap, or creates it when the account has none (D-40).
   * Needs the current PIN (one evaluation) or the phrase; with no PIN set, the phrase (D-41).
   * Throws `WRONG_CREDENTIAL`, `PIN_NOT_SET_UP`, `MALFORMED_RECORD` (neither), `PIN_RATE_LIMITED`,
   * `STALE_VERSION`.
   */
  async changePin(newPin: string, credential: { currentPin: string } | { phrase: string }): Promise<void> {
    const account = this.#requireAccount();
    const { currentPin, phrase } = (credential ?? {}) as { currentPin?: unknown; phrase?: unknown };
    if (typeof phrase === "string") await verifyPhrase(this.#ports, account, phrase);
    else if (typeof currentPin === "string") await verifyPin(this.#ports, account, currentPin);
    else throw new ConvoyError("MALFORMED_RECORD");
    const wrap = await pinWrap(this.#ports, account, newPin);
    const current = await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: account.version, method: "pin" });
    await commit(this.#ports, current ? replaceWrap(wrap) : [createWrap(wrap)]);
  }

  /**
   * Every device wrap at the current version: its `deviceId`, and whether it is this device (§5.5).
   * Names and dates are the integration's, keyed by `deviceId`, for display only.
   */
  async listDevices(): Promise<DeviceEntry[]> {
    const account = this.#requireAccount();
    const wraps = await callPort(() =>
      this.#ports.store.list({ type: "account-key-wrap", accountId: this.accountId, accountKeyVersion: account.version }),
    );
    const expected = { accountId: this.accountId, accountKeyVersion: account.version };
    const local = await callPort(() => this.#ports.deviceKeys.getDevice(this.accountId));
    return wraps
      .filter((json) => (json as { method?: unknown }).method === "device")
      .map((json) => parseAccountKeyWrap(json, { ...expected, method: "device" }).deviceId!)
      .map((deviceId) => ({ deviceId, current: deviceId === local?.deviceId }));
  }

  /** Deletes a device's wrap: it can't unlock again (§5.5, SP-10). */
  async revokeDevice(deviceId: string): Promise<void> {
    const account = this.#requireAccount();
    await commit(this.#ports, [{ op: "delete", key: wrapKey({ accountId: this.accountId, accountKeyVersion: account.version, method: "device", deviceId }) }]);
    const local = await callPort(() => this.#ports.deviceKeys.getDevice(this.accountId));
    if (local?.deviceId === deviceId) await callPort(() => this.#ports.deviceKeys.deleteDevice(this.accountId));
  }

  /**
   * Rotates the account key (§5.7). Needs the current `phrase`, which it keeps (D-41); without a
   * `newPin`, the account has no PIN until `changePin` (D-40). Other devices must register again.
   * Throws `WRONG_CREDENTIAL`, `RECOVERY_NOT_SET_UP`, `PIN_RATE_LIMITED`, `STALE_VERSION`,
   * `MALFORMED_RECORD` (no phrase).
   */
  async rotate(input: { phrase: string; newPin?: string }): Promise<void> {
    const current = this.#requireAccount();
    const { account } = await rotateAccount(this.#ports, current, input);
    this.lock();
    this.#account = account;
  }

  /**
   * After a device that may have been misused, a leaked PIN or phrase, or a support restore
   * (§5.11, D-36): rotates the account key with a new PIN, or none when the PIN budget is spent
   * (D-40, TH-44), which cuts every other device, then re-keys every team with a recovery proof
   * that owners' `reconcile` approves. With `newPhrase`, the phrase `beginRecoverySetup` showed,
   * typed back, it also replaces the phrase; the proofs are still made with `phrase` (D-45). Run
   * it on a device the attacker didn't control. Retry a failed team with `rekey(teamId, { phrase })`.
   * Throws `WRONG_CREDENTIAL`, `RECOVERY_NOT_SET_UP`, `PIN_RATE_LIMITED`, `STALE_VERSION`.
   */
  async secureAccount(input: { phrase: string; newPhrase?: string; newPin?: string }): Promise<RekeyReport> {
    const current = this.#requireAccount();
    const recoveryPublicKey = await currentRecoveryKey(this.#ports, current);
    if (!recoveryPublicKey) throw new ConvoyError("RECOVERY_NOT_SET_UP");
    const pending = this.#pendingPhrase;
    if (input.newPhrase !== undefined && (pending === null || !samePhrase(input.newPhrase, pending))) throw new ConvoyError("WRONG_CREDENTIAL");
    const signer = recoverySigner(this.#ports, this.accountId, input.phrase, recoveryPublicKey);
    try {
      const pin = input.newPin !== undefined ? { newPin: input.newPin } : {};
      const phrases = input.newPhrase !== undefined ? { phrase: input.phrase, newPhrase: pending! } : { phrase: input.phrase };
      const { account } = await rotateAccount(this.#ports, current, { ...pin, ...phrases });
      this.lock();
      this.#account = account;
      // The new keys carry the new version's recovery key; the proof is by the current one (D-45).
      const next = input.newPhrase !== undefined ? await currentRecoveryKey(this.#ports, account) : recoveryPublicKey;
      return await rekeyTeams(this.#ports, account, await accountTeams(this.#ports, account), next!, signer);
    } finally {
      this.#ports.suite.wipe(signer.secretKey);
    }
  }

  /** Whether the account is set up, the vault unlocked, and this device registered (§12). Never calls the OPRF. */
  async status(): Promise<VaultStatus> {
    const version = await callPort(() => this.#ports.store.getAccountKeyVersion(this.accountId));
    if (version === null) return { account: "not-set-up", deviceRegistered: false, deviceId: null, recovery: "not-set-up", pin: "not-set-up" };
    const has = async (method: "recovery" | "pin") =>
      (await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method })) ? "set-up" : "not-set-up";
    const [recovery, pin] = await Promise.all([has("recovery"), has("pin")]);
    const device = await callPort(() => this.#ports.deviceKeys.getDevice(this.accountId));
    const wrap = device
      ? await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "device", deviceId: device.deviceId })
      : null;
    return { account: this.#account ? "unlocked" : "locked", deviceRegistered: wrap !== null, deviceId: device?.deviceId ?? null, recovery, pin };
  }

  /** What the user should act on (§12): recovery not set up, teams whose keys predate the current phrase. */
  async warnings(): Promise<VaultWarning[]> {
    const account = this.#requireAccount();
    const warnings: VaultWarning[] = [];
    if (!(await fetchWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: account.version, method: "pin" }))) {
      warnings.push({ code: "pin-not-set-up", teamIds: [], action: "changePin" });
    }
    const recovery = await currentRecoveryKey(this.#ports, account);
    if (!recovery) return [{ code: "recovery-not-set-up", teamIds: [], action: "beginRecoverySetup" }, ...warnings];
    const stale = await teamsWithOldRecoveryKey(this.#ports, account, recovery);
    if (stale.length > 0) warnings.push({ code: "rekey-needed", teamIds: stale, action: "rekey" });
    const foreign = await teamsWithForeignKeys(this.#ports, account);
    if (foreign.length > 0) warnings.push({ code: "foreign-member-keys", teamIds: foreign, action: "rekey" });
    return warnings;
  }

  /** Creates a team with this account as its first owner (§6.3). Throws `STALE_VERSION` if it exists. */
  async createTeam(teamId: string): Promise<void> {
    const account = this.#requireAccount();
    const version = await nextMemberKeysVersion(this.#ports, account, teamId);
    await commit(this.#ports, newTeamOps(this.#ports, account, teamId, await recoveryPublicKey(this.#ports, account), version));
  }

  /**
   * Creates this account's member keys for a team, if it has none; it stays `pending` until an
   * owner approves them (§6.4). Pass the invite link's `anchor`: the served chain must contain it,
   * checked before anything is written, and the keys carry it as their floor, so every device and
   * context starts from it (D-48). Open the team then, here or in another context. Throws
   * `RECOVERY_NOT_SET_UP`, `MALFORMED_RECORD`, `UNSUPPORTED_VERSION`, `TRUST_FAILURE`.
   */
  async joinTeam(teamId: string, options: { anchor?: string } = {}): Promise<void> {
    const account = this.#requireAccount();
    const floor = options.anchor !== undefined ? decodeAnchor(options.anchor) : undefined;
    if ((await openBundles(this.#ports, account, teamId)).length > 0) return;
    if (floor) await verifiedChain(this.#ports, teamId, [floor]);
    const keys = { recoveryPublicKey: await recoveryPublicKey(this.#ports, account), ...(floor ? { floor } : {}) };
    await commit(this.#ports, newMemberKeys(this.#ports, account, teamId, await nextMemberKeysVersion(this.#ports, account, teamId), keys).ops);
  }

  /**
   * Opens a team in the vault's own context: hands the session only this team's member keys
   * (§5.8, SP-02). Needs `anchors`. A device with no anchor starts from the keys' floor (D-48).
   */
  async openTeam(teamId: string): Promise<TeamSession> {
    return openSession(this.#ports, this.#requireAccount(), teamId);
  }

  /**
   * One team's member keys sealed to a receiver in another context (§3.8, D-29). Deciding which
   * context may ask is the integration's. Throws `MALFORMED_RECORD`, `UNSUPPORTED_VERSION`, `NOT_GRANTED`.
   */
  async exportTeamKeys(teamId: string, request: string): Promise<string> {
    return exportBundles(this.#ports, this.#requireAccount(), teamId, request);
  }

  /**
   * New member keys for a team (§6.8 step 1). With a recovery `phrase` they are proven: the
   * current one, or, after a replacement, the old one the team's keys still carry (D-49). Owners'
   * `reconcile` then approves them (SP-23); otherwise an owner approves by hand. They receive
   * nothing until an owner approves them by rotating. Throws `NOT_GRANTED`, `RECOVERY_NOT_SET_UP`,
   * `WRONG_CREDENTIAL` (a phrase neither current nor carried by the team's keys).
   */
  async rekey(teamId: string, options: { phrase?: string } = {}): Promise<void> {
    const account = this.#requireAccount();
    const recovery = await recoveryPublicKey(this.#ports, account);
    const carried = (await openBundles(this.#ports, account, teamId)).map((b) => b.published.recoveryPublicKey);
    const signer = options.phrase !== undefined ? recoverySigner(this.#ports, this.accountId, options.phrase, [recovery, ...carried]) : undefined;
    try {
      await rekeyTeam(this.#ports, account, teamId, recovery, signer);
    } finally {
      if (signer) this.#ports.suite.wipe(signer.secretKey);
    }
  }

  /**
   * Deletes this account's keys and state for a team (§5.9), after verifying the chain here.
   * Throws `LAST_OWNER` for the only owner, `TRUST_FAILURE` if the chain doesn't verify.
   */
  async leaveTeam(teamId: string): Promise<void> {
    const account = this.#requireAccount();
    const owners = await currentOwners(this.#ports, account, teamId);
    if (owners.length === 1 && owners[0] === this.accountId) throw new ConvoyError("LAST_OWNER");
    const bundles = await openBundles(this.#ports, account, teamId);
    await commit(this.#ports, [
      ...bundles.map((b) => ({
        op: "delete" as const,
        key: { type: "member-keys-wrap" as const, accountId: this.accountId, teamId, memberKeysVersion: b.memberKeysVersion, accountKeyVersion: account.version },
      })),
      { op: "delete", key: { type: "team-state", accountId: this.accountId, teamId } },
    ]);
    if (this.#ports.anchors) await callPort(() => this.#ports.anchors!.deleteAnchor(this.accountId, teamId));
  }

  /** Registers this device unless it has a live wrap at the account's version (§5.5). */
  async #registration(account: OpenAccount): Promise<{ ops: WriteOp[]; device: LocalDevice | null }> {
    const local = await callPort(() => this.#ports.deviceKeys.getDevice(this.accountId));
    if (local) {
      const expected = { accountId: this.accountId, accountKeyVersion: account.version, method: "device", deviceId: local.deviceId } as const;
      if (await fetchWrap(this.#ports, expected)) return { ops: [], device: null };
    }
    const { device, op } = newDevice(this.#ports, account);
    return { ops: [op], device };
  }

  /** Kept only once its wrap is stored. */
  async #keepDevice(device: LocalDevice | null) {
    if (device) await callPort(() => this.#ports.deviceKeys.setDevice(this.accountId, device));
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
