// The account vault (§5, D-03): the only holder of the account key.
import { decodeAnchor } from "../encoding/link.js";
import { ConvoyError, isConvoyError, malformed } from "../errors.js";
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
import type { KeyPair } from "../suites/suite.js";
import type { TeamSession } from "../team/session.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { createWrap, replaceWrap, wrapKey } from "./context.js";
import { deriveRecoveryKeys } from "./recovery-key.js";
import {
  accountTeams,
  storedRecoveryKey,
  oldPhraseSigner,
  phrasePublicKey,
  productTeams,
  recoverySigningKey,
  typedPhrase,
  rekeyTeam,
  rekeyTeams,
  samePhrase,
  teamsWithForeignKeys,
  teamsWithOldRecoveryKey,
  type RekeyReport,
} from "./recovery.js";
import { rotateAccount } from "./rotation.js";
import { verifiedChain } from "../team/load.js";
import { currentOwners, exportBundles, newMemberKeys, newTeamOps, nextMemberKeysVersion, openBundles, openSession, recordVaultAnchor, vaultAnchorOf } from "./member-custody.js";
import {
  acceptVersion,
  commit,
  currentVersion,
  openDeviceWrap,
  readWrap,
  newDevice,
  openWithPin,
  pinWrap,
  recoveryPublicKey,
  recoveryWrap,
  verifyPhrase,
  verifyPin,
} from "./unlock-methods.js";
import { refusedKdf } from "./pin-key.js";

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
  readonly code: "recovery-not-set-up" | "pin-not-set-up" | "rekey-needed" | "foreign-member-keys" | "pin-upgrade-failed" | "recovery-key-mismatch";
  /**
   * For `rekey-needed`: teams whose member keys don't carry the current recovery key; re-key each with
   * the phrase, whose key is taken as typed, never the stored one (D-56). For `foreign-member-keys`:
   * teams with keys published under the account that this vault didn't make, or whose keys fail their
   * checks, which a withheld record causes too (D-43, D-58): someone likely holds the session; end other
   * sessions, then `secureAccount`. Only teams where the vault holds keys are listed (TH-37).
   */
  readonly teamIds: readonly string[];
  /**
   * `report` for `pin-upgrade-failed` with a failed proof: the OPRF service answered with a key
   * the client doesn't pin (TH-51); `changePin` for any other upgrade failure.
   */
  readonly action: "beginRecoverySetup" | "changePin" | "rekey" | "report" | "secureAccount";
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
  for (const key of ports.settings.oprf.keys.values()) if (!ports.suite.oprfPublicKeyValid(key)) throw malformed();
  return new Vault(ports, accountId);
}

/** Library-only access to the vault's ports and open account key. Never exported from the package entry (D-15). */
interface VaultInternals {
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
  /** Set when a PIN wrap's upgrade failed: reported, and not tried again by this vault (§5.4). */
  #upgradeFailure: ConvoyError | null = null;
  /** Set when the recovery wrap names another key than the phrase typed: rewritten by an account-key holder (D-56). */
  #recoveryMismatch = false;

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
   * needs the current PIN (D-61). Throws `WRONG_CREDENTIAL` (not the phrase shown, or not a current
   * credential), `MALFORMED_RECORD` (no credential), `PIN_NOT_SET_UP`, `PIN_RATE_LIMITED`, `STALE_VERSION`.
   */
  async confirmRecoveryPhrase(phrase: string, options: { currentPhrase?: string; currentPin?: string } = {}): Promise<RekeyReport> {
    const account = this.#requireAccount();
    const pending = this.#pendingPhrase;
    if (pending === null || !samePhrase(phrase, pending)) throw new ConvoyError("WRONG_CREDENTIAL");
    // A wrap that doesn't parse or whose key can't be read is still replaced, never read (D-56).
    const old = (await storedRecoveryKey(this.#ports, account)).present;
    const { currentPhrase, currentPin } = options ?? {};
    // Every setup needs a current credential: with no recovery wrap, the PIN; whoever deletes it chooses nothing (D-61).
    if (!old || typeof currentPhrase !== "string") {
      if (typeof currentPin !== "string") throw new ConvoyError("MALFORMED_RECORD");
      await verifyPin(this.#ports, account, currentPin);
    }
    // The current phrase opens the recovery wrap; its own key signs, never the one the wrap names (D-56).
    const signer = old && typeof currentPhrase === "string" ? (await typedPhrase(this.#ports, account, currentPhrase)).signing : undefined;
    try {
      const wrap = recoveryWrap(this.#ports, account, pending);
      const next = openRecoveryPublicKey(wrap, account.key);
      // Listed before anything is written: a store error then writes nothing, and the pending phrase is kept (§5.6).
      const teams = await teamsWithOldRecoveryKey(this.#ports, account, next);
      await commit(this.#ports, old ? replaceWrap(wrap) : [createWrap(wrap)]);
      this.#pendingPhrase = null;
      this.#recoveryMismatch = false;
      return await rekeyTeams(this.#ports, account, teams, next, signer);
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
    // A device wrap that can't be read, or doesn't open, is no registration: the device registers again (D-58).
    const key = await openDeviceWrap(this.#ports, this.accountId, version, device);
    if (!key) throw new ConvoyError("DEVICE_NOT_REGISTERED");
    await this.#open({ accountId: this.accountId, version, key });
  }

  /**
   * Unlocks with the PIN (§5.4), registers this device if needed, and upgrades an
   * outdated PIN wrap. Throws `WRONG_CREDENTIAL`, `PIN_RATE_LIMITED`, `PIN_NOT_SET_UP` (no PIN, D-40),
   * `MALFORMED_RECORD`.
   */
  async unlockWithPin(pin: string): Promise<void> {
    const version = await this.#requireVersion();
    const read = await readWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "pin" });
    // Rotated with the phrase alone (D-40): no PIN until one is set, and no evaluation spent.
    if (read.state === "absent") throw new ConvoyError("PIN_NOT_SET_UP");
    // One that can't be read can't be opened: no evaluation spent either (D-58).
    if (read.state === "unreadable") throw new ConvoyError("WRONG_CREDENTIAL");
    const { wrap } = read;
    const account = { accountId: this.accountId, version, key: await openWithPin(this.#ports, wrap, pin, "unlock") };

    const { ops, device } = await this.#registration(account);
    const { argon2, oprf } = this.#ports.settings;
    const kdf = wrap.kdf!;
    // The key id is the settings', never the server's (D-53).
    const outdated = kdf.opslimit < argon2.write.opslimit || kdf.memlimit < argon2.write.memlimit || (oprf.writeKeyId !== null && kdf.oprfKeyId !== oprf.writeKeyId);
    if (outdated && !this.#upgradeFailure) {
      try {
        ops.push(...replaceWrap(await pinWrap(this.#ports, account, pin)));
      } catch (error) {
        // The PIN was verified: only the upgrade failed, so the unlock stands with the old wrap; it is
        // reported, and not tried again here, so it never spends an evaluation per unlock (§5.4).
        if (!isConvoyError(error)) throw error;
        this.#upgradeFailure = error;
      }
    }
    if (ops.length > 0) await commit(this.#ports, ops);
    await this.#keepDevice(device);
    await this.#open(account);
  }

  /**
   * Unlocks with the recovery phrase and registers this device, then sets a new PIN (§5.4).
   * If only the new PIN fails (`PIN_RATE_LIMITED`), the vault stays unlocked: call `changePin` later.
   * A recovery wrap naming another key than the phrase's is reported (`recovery-key-mismatch`, D-56).
   */
  async recover(phrase: string, newPin: string): Promise<void> {
    const { suite } = this.#ports;
    const version = await this.#requireVersion();
    const read = await readWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method: "recovery" });
    if (read.state === "absent") throw new ConvoyError("RECOVERY_NOT_SET_UP");
    if (read.state === "unreadable") throw new ConvoyError("WRONG_CREDENTIAL");
    const { wrap } = read;
    const { recoveryKey, signing } = deriveRecoveryKeys(suite, this.accountId, phrase);
    let key: Uint8Array;
    try {
      key = openAccountKeyWrap(wrap, recoveryKey);
      // Another key than this phrase's, or one that can't be read: reported, never refused, so `secureAccount` can repair it (§4.1, D-56).
      let stored: Uint8Array | null = null;
      try {
        stored = openRecoveryPublicKey(wrap, key);
      } catch (error) {
        if (!isConvoyError(error)) throw error;
      }
      if (stored === null || !suite.equal(stored, signing.publicKey)) this.#recoveryMismatch = true;
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
    // A live wrap is replaced, read or not: one that can't be read costs the PIN only (D-58).
    const current = await readWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: account.version, method: "pin" });
    await commit(this.#ports, current.state !== "absent" ? replaceWrap(wrap) : [createWrap(wrap)]);
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
    // A device wrap that doesn't parse is left out: it was never a device of the account's (D-58).
    const deviceIds: string[] = [];
    for (const json of wraps.filter((w) => (w as { method?: unknown }).method === "device")) {
      try {
        deviceIds.push(parseAccountKeyWrap(json, { ...expected, method: "device" }).deviceId!);
      } catch (error) {
        if (!isConvoyError(error)) throw error;
      }
    }
    return deviceIds.map((deviceId) => ({ deviceId, current: deviceId === local?.deviceId }));
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
    this.#recoveryMismatch = false;
  }

  /**
   * After a device that may have been misused, a leaked PIN or phrase, or a support restore
   * (§5.11, D-36): rotates the account key with a new PIN, or none when the PIN budget is spent
   * (D-40, TH-44), which cuts every other device, then re-keys every team with a recovery proof
   * that owners' `reconcile` approves. With `newPhrase`, the phrase `beginRecoverySetup` showed,
   * typed back, it also replaces the phrase; the proofs are still made with `phrase` (D-45). The new
   * keys carry the typed phrase's key, never the one the recovery wrap names, which this repairs (D-56). A new
   * phrase and a different PIN are recommended: the retired version still opens with the old ones
   * (SP-19), and a `newPin` that opens the current PIN wrap is refused. Each new floor comes from a
   * chain containing every root the vault holds, or from `anchors[teamId]`, an anchor an owner gave
   * (D-54). Run it on a device the attacker didn't control. Retry a failed team with
   * `rekey(teamId, { phrase, oldPhrase?, anchor? })`: with `newPhrase`, that one as `phrase` and this one as
   * `oldPhrase`. `teamIds`, the teams the product says the user is in, makes a team with no wrap that
   * opens a failure too, repaired by `rekey` with an owner's anchor (D-60). Throws `WRONG_CREDENTIAL`, `RECOVERY_NOT_SET_UP`,
   * `PIN_RATE_LIMITED`, `STALE_VERSION`, `MALFORMED_RECORD`, `UNSUPPORTED_VERSION`.
   */
  async secureAccount(input: {
    phrase: string;
    newPhrase?: string;
    newPin?: string;
    anchors?: Readonly<Record<string, string>>;
    teamIds?: readonly string[];
  }): Promise<RekeyReport> {
    const current = this.#requireAccount();
    // Checked by opening the recovery wrap, so a rewritten public key doesn't refuse the real phrase (D-56).
    const signer = (await typedPhrase(this.#ports, current, input.phrase)).signing;
    try {
      const pending = this.#pendingPhrase;
      if (input.newPhrase !== undefined && (pending === null || !samePhrase(input.newPhrase, pending))) throw new ConvoyError("WRONG_CREDENTIAL");
      const anchors = new Map(Object.entries(input.anchors ?? {}).map(([teamId, anchor]) => [teamId, decodeAnchor(anchor)]));
      const listed = productTeams(input.teamIds);
      // Listed before anything is written, so a store error writes nothing; a rotation re-wraps the same teams (§5.11, D-58).
      const teams = await accountTeams(this.#ports, current);
      if (input.newPin !== undefined) await this.#refuseCurrentPin(current, input.newPin);
      const pin = input.newPin !== undefined ? { newPin: input.newPin } : {};
      const phrases = input.newPhrase !== undefined ? { phrase: input.phrase, newPhrase: pending! } : { phrase: input.phrase };
      const { account } = await rotateAccount(this.#ports, current, { ...pin, ...phrases });
      this.lock();
      this.#account = account;
      this.#recoveryMismatch = false;
      // The new keys carry the typed phrase's key, the new one if given, never one read back; the proof is by the current one (D-45, D-56).
      const next = input.newPhrase !== undefined ? phrasePublicKey(this.#ports, this.accountId, pending!) : signer.publicKey;
      // Floors only where every root agrees, or from an owner's anchor: a planted floor fails its team (D-54).
      // Teams the product lists with no wrap that opens: their keys were removed; reported, never skipped (D-60).
      const missing = listed.filter((teamId) => !teams.includes(teamId));
      return await rekeyTeams(this.#ports, account, teams, next, signer, anchors, missing);
    } finally {
      this.#ports.suite.wipe(signer.secretKey);
    }
  }

  /**
   * A new PIN that opens the current PIN wrap would leave the retired version opening with it
   * (SP-19): `MALFORMED_RECORD`. One evaluation, from the `enroll` share the new PIN wrap draws on too:
   * when it is spent the check is skipped, and setting the new PIN fails as well (D-40, TH-44).
   * A wrap whose `kdf` the reader refuses can't be opened either: no check (D-58).
   */
  async #refuseCurrentPin(account: OpenAccount, newPin: string): Promise<void> {
    // No wrap, or one that can't be read: nothing the new PIN could open, so no check (D-58).
    const read = await readWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: account.version, method: "pin" });
    if (read.state !== "readable") return;
    // One whose `kdf` the reader refuses (an unpinned key id, a cost below the minimum) can't be opened either (D-58).
    const { settings } = this.#ports;
    if (refusedKdf(read.wrap.kdf!, settings.argon2.min, settings.oprf.keys)) return;
    try {
      this.#ports.suite.wipe(await openWithPin(this.#ports, read.wrap, newPin, "enroll"));
    } catch (error) {
      if (isConvoyError(error, "WRONG_CREDENTIAL") || isConvoyError(error, "PIN_RATE_LIMITED")) return;
      throw error;
    }
    throw malformed();
  }

  /** Whether the account is set up, the vault unlocked, and this device registered (§12). Never calls the OPRF. */
  async status(): Promise<VaultStatus> {
    const version = await callPort(() => this.#ports.store.getAccountKeyVersion(this.accountId));
    if (version === null) return { account: "not-set-up", deviceRegistered: false, deviceId: null, recovery: "not-set-up", pin: "not-set-up" };
    // A wrap that can't be read still says the method is set up; `warnings()` names it (D-58).
    const has = async (method: "recovery" | "pin") =>
      (await readWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: version, method })).state !== "absent" ? "set-up" : "not-set-up";
    const [recovery, pin] = await Promise.all([has("recovery"), has("pin")]);
    const device = await callPort(() => this.#ports.deviceKeys.getDevice(this.accountId));
    const registered = device ? await this.#registered(version, device) : false;
    return { account: this.#account ? "unlocked" : "locked", deviceRegistered: registered, deviceId: device?.deviceId ?? null, recovery, pin };
  }

  /** What the user should act on (§12): recovery not set up, teams whose keys predate the current phrase. */
  async warnings(): Promise<VaultWarning[]> {
    const account = this.#requireAccount();
    const warnings: VaultWarning[] = [];
    // No PIN wrap, or one that can't be read: set a PIN (D-40, D-58).
    if ((await readWrap(this.#ports, { accountId: this.accountId, accountKeyVersion: account.version, method: "pin" })).state !== "readable") {
      warnings.push({ code: "pin-not-set-up", teamIds: [], action: "changePin" });
    }
    const recovery = await storedRecoveryKey(this.#ports, account);
    if (!recovery.present) return [{ code: "recovery-not-set-up", teamIds: [], action: "beginRecoverySetup" }, ...warnings];
    const foreign = await teamsWithForeignKeys(this.#ports, account);
    // A team whose keys fail is answered with secureAccount, not rekey: listed once, under foreign keys (D-58).
    // With a stored key that can't be read, which teams carry it can't be told: the mismatch is reported instead (D-56).
    if (recovery.key) {
      const stale = (await teamsWithOldRecoveryKey(this.#ports, account, recovery.key)).filter((teamId) => !foreign.includes(teamId));
      if (stale.length > 0) warnings.push({ code: "rekey-needed", teamIds: stale, action: "rekey" });
    }
    // Keys this vault didn't make: someone holds the session or the old account key (D-54).
    if (foreign.length > 0) warnings.push({ code: "foreign-member-keys", teamIds: foreign, action: "secureAccount" });
    if (this.#upgradeFailure) {
      const proof = isConvoyError(this.#upgradeFailure, "TRUST_FAILURE");
      warnings.push({ code: "pin-upgrade-failed", teamIds: [], action: proof ? "report" : "changePin" });
    }
    // A recovery wrap that doesn't parse can't be checked against the phrase: a new setup with the PIN replaces it (D-58).
    if (!recovery.parsed) warnings.push({ code: "recovery-key-mismatch", teamIds: [], action: "beginRecoverySetup" });
    else if (this.#recoveryMismatch || !recovery.key) warnings.push({ code: "recovery-key-mismatch", teamIds: [], action: "secureAccount" });
    return warnings;
  }

  /** Creates a team with this account as its first owner (§6.3). Throws `STALE_VERSION` if it exists. */
  async createTeam(teamId: string): Promise<void> {
    const account = this.#requireAccount();
    const version = await nextMemberKeysVersion(this.#ports, account, teamId);
    const { ops, floor } = newTeamOps(this.#ports, account, teamId, await recoveryPublicKey(this.#ports, account), version);
    await commit(this.#ports, ops);
    // The vault's anchor is the version it just wrote, never read back from the server.
    await recordVaultAnchor(this.#ports, this.accountId, teamId, floor);
  }

  /**
   * Creates this account's member keys for a team, if it has none; it stays `pending` until an
   * owner approves them (§6.4). Verifies the served chain first, from the invite link's `anchor`
   * if given and the vault's own anchor if it has one (D-59), else from version 1 (a first contact); the keys carry its tip as their
   * floor, so every device and context starts from it (D-48, D-50). With keys already, only checks
   * the anchor. Open the team then, here or in another context. Throws `RECOVERY_NOT_SET_UP`,
   * `MALFORMED_RECORD`, `UNSUPPORTED_VERSION`, `TRUST_FAILURE`.
   */
  async joinTeam(teamId: string, options: { anchor?: string } = {}): Promise<void> {
    const account = this.#requireAccount();
    // The invite anchor and the vault's own anchor: a chain without both is refused (D-59).
    const vault = await vaultAnchorOf(this.#ports, this.accountId, teamId);
    const anchors = [...(options.anchor !== undefined ? [decodeAnchor(options.anchor)] : []), ...(vault ? [vault] : [])];
    const [held] = await openBundles(this.#ports, account, teamId);
    if (held) {
      // With keys already, only check, against every root the vault holds: the floor too (D-59).
      const roots = [...anchors, held.floor];
      if (roots.length > 0) await verifiedChain(this.#ports, teamId, roots);
      return;
    }
    const recovery = await recoveryPublicKey(this.#ports, account);
    const chain = await verifiedChain(this.#ports, teamId, anchors);
    const tip = chain.records.at(-1)!;
    const floor = { version: tip.version, hash: chain.hashes.get(tip.version)! };
    await commit(this.#ports, newMemberKeys(this.#ports, account, teamId, await nextMemberKeysVersion(this.#ports, account, teamId), { recoveryPublicKey: recovery, floor }).ops);
    await recordVaultAnchor(this.#ports, this.accountId, teamId, floor);
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
   * New member keys for a team (§6.8 step 1). With the current recovery `phrase` they carry its
   * key and are proven by it; after a replacement, `oldPhrase`, which the team's keys still carry,
   * proves them instead (D-49, D-56). Owners' `reconcile` then approves them (SP-23); otherwise an
   * owner approves by hand. They receive nothing until an owner approves them by rotating. With an
   * owner's `anchor`, it runs even when no wrap opens for the team (D-59). Throws
   * `NOT_GRANTED`, `RECOVERY_NOT_SET_UP`, `WRONG_CREDENTIAL` (a `phrase` that isn't current, an
   * `oldPhrase` the team's keys don't carry), `MALFORMED_RECORD` (`oldPhrase` without `phrase`).
   */
  async rekey(teamId: string, options: { phrase?: string; oldPhrase?: string; anchor?: string } = {}): Promise<void> {
    const account = this.#requireAccount();
    const { phrase, oldPhrase } = options;
    if (oldPhrase !== undefined && phrase === undefined) throw malformed();
    const ownerAnchor = options.anchor !== undefined ? decodeAnchor(options.anchor) : undefined;
    let recovery: Uint8Array;
    let signer: KeyPair | undefined;
    if (phrase !== undefined) {
      // The keys carry the typed phrase's key, never the one the wrap names (D-56).
      const typed = await typedPhrase(this.#ports, account, phrase);
      if (typed.mismatch) this.#recoveryMismatch = true;
      recovery = typed.signing.publicKey;
      if (oldPhrase === undefined) signer = typed.signing;
      else {
        // A retry after a replacement: the old phrase, which the team's held keys carry, signs (D-49).
        this.#ports.suite.wipe(typed.signing.secretKey);
        const carried = (await openBundles(this.#ports, account, teamId)).map((b) => b.published.recoveryPublicKey);
        // With no bundle (a repair with an owner's anchor), nothing to check it against: owners check the proof (D-60).
        signer = carried.length > 0 ? oldPhraseSigner(this.#ports, this.accountId, oldPhrase, carried) : recoverySigningKey(this.#ports, this.accountId, oldPhrase);
      }
    } else {
      recovery = await recoveryPublicKey(this.#ports, account);
    }
    try {
      await rekeyTeam(this.#ports, account, teamId, recovery, signer, ownerAnchor);
    } finally {
      if (signer) this.#ports.suite.wipe(signer.secretKey);
    }
  }

  /**
   * Deletes this account's keys for a team (§5.9), after verifying the chain here.
   * Throws `LAST_OWNER` for a listed owner, who steps down first (D-65), `TRUST_FAILURE` if the chain doesn't verify.
   */
  async leaveTeam(teamId: string): Promise<void> {
    const account = this.#requireAccount();
    const owners = await currentOwners(this.#ports, account, teamId);
    // A listed owner steps down first (setOwners without it): owners never leave the list behind them (D-65).
    if (owners.includes(this.accountId)) throw new ConvoyError("LAST_OWNER");
    const bundles = await openBundles(this.#ports, account, teamId);
    await commit(this.#ports, [
      ...bundles.map((b) => ({
        op: "delete" as const,
        key: { type: "member-keys-wrap" as const, accountId: this.accountId, teamId, memberKeysVersion: b.memberKeysVersion, accountKeyVersion: account.version },
      })),
    ]);
    if (this.#ports.anchors) await callPort(() => this.#ports.anchors!.deleteAnchor(this.accountId, teamId));
    await callPort(() => this.#ports.deviceKeys.deleteVaultAnchor(this.accountId, teamId));
  }

  /** Registers this device unless it has a live wrap at the account's version (§5.5). */
  async #registration(account: OpenAccount): Promise<{ ops: WriteOp[]; device: LocalDevice | null }> {
    const local = await callPort(() => this.#ports.deviceKeys.getDevice(this.accountId));
    if (local) {
      // One that can't be read, or doesn't open, is no registration: a new device registers (D-58).
      if (await this.#registered(account.version, local)) return { ops: [], device: null };
    }
    const { device, op } = newDevice(this.#ports, account);
    return { ops: [op], device };
  }

  /** Whether this device's wrap at `version` opens under its key (D-58). */
  async #registered(version: number, device: LocalDevice): Promise<boolean> {
    const key = await openDeviceWrap(this.#ports, this.accountId, version, device);
    if (key) this.#ports.suite.wipe(key);
    return key !== null;
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
