// Rotating the account key (§5.7, D-10, SP-11).
import { ConvoyError } from "../errors.js";
import { callPort, type WriteOp } from "../ports.js";
import { createMemberKeysWrap, memberKeysWrapToJson } from "../records/member-keys-wrap.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { createWrap } from "./context.js";
import { openedWraps } from "./member-custody.js";
import { commit, deviceWrap, pinWrap, recoveryWrap, verifyPhrase } from "./unlock-methods.js";

/**
 * Re-wraps every member keys bundle under a new account key version, with the current-device
 * wrap, the recovery wrap (the current phrase is required, and kept unless `newPhrase` replaces
 * it, D-41, D-45), and the PIN wrap if a new PIN is given (else no PIN until one is set, D-40),
 * switched in one atomic batch. Member keys don't change, and each bundle keeps its anchor floor
 * (D-52): the floor moves only along a verified chain.
 */
export async function rotateAccount(
  ports: AccountPorts,
  current: OpenAccount,
  input: { phrase: string; newPhrase?: string; newPin?: string },
): Promise<{ account: OpenAccount }> {
  const { suite, deviceKeys } = ports;
  const { accountId } = current;
  // An open vault alone can't rotate (D-41): the current phrase proves the account, and is kept.
  if (typeof input?.phrase !== "string") throw new ConvoyError("MALFORMED_RECORD");
  await verifyPhrase(ports, current, input.phrase);

  const next: OpenAccount = { accountId, version: current.version + 1, key: suite.randomBytes(suite.sizes.key) };
  const ops: WriteOp[] = [];

  // Every wrap that opens, unchecked against its published keys: opening the team checks them, and a
  // rotation can't then be blocked by a planted bundle, nor made to drop a real one (D-58).
  for (const { wrap, bundle } of await openedWraps(ports, current)) {
    const context = { accountId, teamId: wrap.teamId, memberKeysVersion: wrap.memberKeysVersion, accountKeyVersion: next.version };
    const rewrapped = createMemberKeysWrap(suite, context, next.key, bundle);
    suite.wipe(bundle.signingSeed, bundle.encryptionSecretKey, bundle.teamStateKey);
    ops.push({ op: "create", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(rewrapped) });
  }

  if (input.newPin !== undefined) ops.push(createWrap(await pinWrap(ports, next, input.newPin)));
  ops.push(createWrap(recoveryWrap(ports, next, input.newPhrase ?? input.phrase)));
  const device = await callPort(() => deviceKeys.getDevice(accountId));
  if (device) ops.push(createWrap(deviceWrap(ports, next, device)));
  ops.push({ op: "set-account-key-version", accountId, expected: current.version, accountKeyVersion: next.version });

  await commit(ports, ops);
  await callPort(() => deviceKeys.setAccountKeyVersion(accountId, next.version));
  return { account: next };
}
