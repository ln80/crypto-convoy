// The three unlock methods and their wraps (§4.1, §5.3–§5.6).
import { toBase64url } from "../encoding/base64url.js";
import { ConvoyError, StoreConflictError, trustFailure } from "../errors.js";
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
import { deriveRecoveryKeys } from "./recovery-key.js";

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

/** The wrap the caller asked for, or `null` if the server doesn't serve it. */
export async function fetchWrap(
  ports: AccountPorts,
  expected: { accountId: string; accountKeyVersion: number; method: UnlockMethod; deviceId?: string },
): Promise<AccountKeyWrap | null> {
  const json = await callPort(() => ports.store.get(wrapKey(expected)));
  return json === null || json === undefined ? null : parseAccountKeyWrap(json, expected);
}

export async function pinWrap(ports: AccountPorts, account: OpenAccount, pin: string): Promise<AccountKeyWrap> {
  const { suite, oprf, settings } = ports;
  const oprfKeyId = await callPort(() => oprf.currentKeyId(account.accountId));
  const kdf = newKdf(suite, settings.argon2.write, oprfKeyId);
  const pinKey = await derivePinKey(suite, oprf, { accountId: account.accountId, pin, kdf, purpose: "enroll", min: settings.argon2.min });
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
  });
  try {
    return openAccountKeyWrap(wrap, pinKey);
  } finally {
    ports.suite.wipe(pinKey);
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
