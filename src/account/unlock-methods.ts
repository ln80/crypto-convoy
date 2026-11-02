// The three unlock methods and their wraps (§4.1, §5.3–§5.6).
import { toBase64url } from "../encoding/base64url.js";
import { ConvoyError, StoreConflictError, isConvoyError, trustFailure } from "../errors.js";
import { callPort, type LocalDevice, type OprfPurpose, type WriteOp } from "../ports.js";
import {
  createAccountKeyWrap,
  openAccountKeyWrap,
  openRecoveryPublicKey,
  parseAccountKeyWrap,
  type AccountKeyWrap,
  type UnlockMethod,
} from "../records/account-key-wrap.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { createWrap, wrapKey } from "./context.js";
import { derivePinKey, newKdf } from "./pin-key.js";
import { deriveRecoveryKey, deriveRecoveryKeys } from "./recovery-key.js";

/** The server's current account key version, never below the highest this device accepted (SP-07). */
export async function currentVersion(ports: AccountPorts, accountId: string): Promise<number | null> {
  const version = await callPort(() => ports.store.getAccountKeyVersion(accountId));
  const seen = await callPort(() => ports.deviceKeys.getAccountKeyVersion(accountId));
  if (version === null) {
    if (seen !== null) throw trustFailure("rollback");
    return null;
  }
  if (!Number.isSafeInteger(version) || version < 1) throw new ConvoyError("MALFORMED_RECORD");
  if (seen !== null && version < seen) throw trustFailure("rollback");
  return version;
}

export async function acceptVersion(ports: AccountPorts, account: OpenAccount): Promise<void> {
  const seen = await callPort(() => ports.deviceKeys.getAccountKeyVersion(account.accountId));
  if (seen === null || account.version > seen) {
    await callPort(() => ports.deviceKeys.setAccountKeyVersion(account.accountId, account.version));
  }
}

/** A wrap read by its identity: absent, readable, or present but unreadable (D-58). */
type ReadWrap = { readonly state: "absent" } | { readonly state: "readable"; readonly wrap: AccountKeyWrap } | { readonly state: "unreadable" };

/**
 * The wrap the caller asked for. One that doesn't parse, or fails its shape or context checks at a
 * known version and suite, is present but unreadable: it costs that method only (D-58). An unknown
 * version or suite stays `UNSUPPORTED_VERSION`, readers first (§10); a store error, `STORE_ERROR`.
 */
export async function readWrap(
  ports: AccountPorts,
  expected: { accountId: string; accountKeyVersion: number; method: UnlockMethod; deviceId?: string },
): Promise<ReadWrap> {
  const json = await callPort(() => ports.store.get(wrapKey(expected)));
  if (json === null || json === undefined) return { state: "absent" };
  try {
    return { state: "readable", wrap: parseAccountKeyWrap(json, expected) };
  } catch (error) {
    if (isConvoyError(error) && !isConvoyError(error, "UNSUPPORTED_VERSION") && !isConvoyError(error, "STORE_ERROR")) return { state: "unreadable" };
    throw error;
  }
}

/**
 * This device's account key at `version`, or `null` when its wrap is absent, can't be read, or doesn't
 * open under the device key: a random key never fails honestly, so it is no registration (D-58).
 */
export async function openDeviceWrap(ports: AccountPorts, accountId: string, version: number, device: LocalDevice): Promise<Uint8Array | null> {
  const read = await readWrap(ports, { accountId, accountKeyVersion: version, method: "device", deviceId: device.deviceId });
  if (read.state !== "readable") return null;
  try {
    return openAccountKeyWrap(read.wrap, device.deviceKey);
  } catch (error) {
    if (isConvoyError(error, "DECRYPTION_FAILED")) return null;
    throw error;
  }
}

/** The wrap the caller asked for, or `null` if the server doesn't serve it. */
async function fetchWrap(
  ports: AccountPorts,
  expected: { accountId: string; accountKeyVersion: number; method: UnlockMethod; deviceId?: string },
): Promise<AccountKeyWrap | null> {
  const json = await callPort(() => ports.store.get(wrapKey(expected)));
  return json === null || json === undefined ? null : parseAccountKeyWrap(json, expected);
}

export async function pinWrap(ports: AccountPorts, account: OpenAccount, pin: string): Promise<AccountKeyWrap> {
  const { suite, oprf, settings } = ports;
  // The key id new wraps use is a setting, never a server answer (D-53).
  if (settings.oprf.writeKeyId === null) throw new ConvoyError("UNSUPPORTED_VERSION");
  const kdf = newKdf(suite, settings.argon2.write, settings.oprf.writeKeyId);
  const pinKey = await derivePinKey(suite, oprf, { accountId: account.accountId, pin, kdf, purpose: "enroll", min: settings.argon2.min, oprfKeys: settings.oprf.keys });
  try {
    return createAccountKeyWrap(suite, { accountId: account.accountId, accountKeyVersion: account.version, method: "pin", kdf }, pinKey, account.key);
  } finally {
    suite.wipe(pinKey);
  }
}

/** The recovery wrap, carrying the recovery public key under the account key (§4.1). Throws `WRONG_CREDENTIAL`. */
export function recoveryWrap(ports: AccountPorts, account: OpenAccount, phrase: string): AccountKeyWrap {
  const { recoveryKey, signing } = deriveRecoveryKeys(ports.suite, account.accountId, phrase);
  try {
    const context = { accountId: account.accountId, accountKeyVersion: account.version, method: "recovery" } as const;
    return createAccountKeyWrap(ports.suite, context, recoveryKey, account.key, signing.publicKey);
  } finally {
    ports.suite.wipe(recoveryKey, signing.secretKey);
  }
}

/**
 * The account's recovery public key, read authenticated from the recovery wrap at the current
 * version (§4.1). Throws `RECOVERY_NOT_SET_UP` if there is none (D-35).
 */
export async function recoveryPublicKey(ports: AccountPorts, account: OpenAccount): Promise<Uint8Array> {
  const wrap = await fetchWrap(ports, { accountId: account.accountId, accountKeyVersion: account.version, method: "recovery" });
  if (!wrap) throw new ConvoyError("RECOVERY_NOT_SET_UP");
  return openRecoveryPublicKey(wrap, account.key);
}

/** A new device key and its wrap (§5.5). The caller commits the op, then keeps the device. */
export function newDevice(ports: AccountPorts, account: OpenAccount): { device: LocalDevice; op: WriteOp } {
  const { suite } = ports;
  const device = { deviceId: toBase64url(suite.randomBytes(16)), deviceKey: suite.randomBytes(suite.sizes.key) };
  return { device, op: createWrap(deviceWrap(ports, account, device)) };
}

export function deviceWrap(ports: AccountPorts, account: OpenAccount, device: LocalDevice): AccountKeyWrap {
  return createAccountKeyWrap(
    ports.suite,
    { accountId: account.accountId, accountKeyVersion: account.version, method: "device", deviceId: device.deviceId },
    device.deviceKey,
    account.key,
  );
}

export async function openWithPin(ports: AccountPorts, wrap: AccountKeyWrap, pin: string, purpose: OprfPurpose): Promise<Uint8Array> {
  const pinKey = await derivePinKey(ports.suite, ports.oprf, {
    accountId: wrap.accountId,
    pin,
    kdf: wrap.kdf!,
    purpose,
    min: ports.settings.argon2.min,
    oprfKeys: ports.settings.oprf.keys,
  });
  try {
    return openAccountKeyWrap(wrap, pinKey);
  } finally {
    ports.suite.wipe(pinKey);
  }
}

/**
 * Checks the current PIN against the live PIN wrap (§5.6, D-41): one server evaluation.
 * Throws `PIN_NOT_SET_UP`, `WRONG_CREDENTIAL`, `PIN_RATE_LIMITED`.
 */
export async function verifyPin(ports: AccountPorts, account: OpenAccount, pin: string): Promise<void> {
  const read = await readWrap(ports, { accountId: account.accountId, accountKeyVersion: account.version, method: "pin" });
  if (read.state === "absent") throw new ConvoyError("PIN_NOT_SET_UP");
  // A wrap that can't be read can't be opened: no evaluation spent on it (D-58).
  if (read.state === "unreadable") throw new ConvoyError("WRONG_CREDENTIAL");
  sameKey(ports, account, await openWithPin(ports, read.wrap, pin, "unlock"));
}

/** Checks the current phrase against the live recovery wrap (§5.6, D-41). Throws `RECOVERY_NOT_SET_UP`, `WRONG_CREDENTIAL`. */
export async function verifyPhrase(ports: AccountPorts, account: OpenAccount, phrase: string): Promise<void> {
  const read = await readWrap(ports, { accountId: account.accountId, accountKeyVersion: account.version, method: "recovery" });
  if (read.state === "absent") throw new ConvoyError("RECOVERY_NOT_SET_UP");
  if (read.state === "unreadable") throw new ConvoyError("WRONG_CREDENTIAL");
  const { wrap } = read;
  const recoveryKey = deriveRecoveryKey(ports.suite, account.accountId, phrase);
  let key: Uint8Array;
  try {
    key = openAccountKeyWrap(wrap, recoveryKey);
  } finally {
    ports.suite.wipe(recoveryKey);
  }
  sameKey(ports, account, key);
}

/** The key a credential opened must be the open account key; wipes it either way. */
function sameKey(ports: AccountPorts, account: OpenAccount, key: Uint8Array): void {
  try {
    if (!ports.suite.equal(key, account.key)) throw new ConvoyError("WRONG_CREDENTIAL");
  } finally {
    ports.suite.wipe(key);
  }
}

/** Commits, turning a refused write into `STALE_VERSION` (§12). */
export async function commit(ports: AccountPorts, ops: readonly WriteOp[]): Promise<void> {
  try {
    await callPort(() => ports.store.commit(ops));
  } catch (error) {
    if (error instanceof StoreConflictError) throw new ConvoyError("STALE_VERSION");
    throw error;
  }
}
