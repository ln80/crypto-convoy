// Rotating the account key (§5.7, D-10, SP-11).
import { ConvoyError } from "../errors.js";
import { callPort, type WriteOp } from "../ports.js";
import { openAccountKeyWrap } from "../records/account-key-wrap.js";
import { parseMemberKeys } from "../records/member-keys.js";
import {
  createMemberKeysWrap,
  memberKeysWrapToJson,
  openMemberKeysWrap,
  parseMemberKeysWrap,
} from "../records/member-keys-wrap.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { createWrap } from "./context.js";
import { deriveRecoveryKey } from "./recovery-key.js";
import { commit, deviceWrap, fetchWrap, pinWrap, recoveryWrap } from "./unlock-methods.js";

/**
 * Re-wraps every member keys bundle under a new account key version, with the current-device
 * wrap, the PIN wrap if a PIN is given (else no PIN until one is set, D-40), and the recovery
 * wrap if the phrase is given (else recovery must be set up again, D-35), switched in one atomic
 * batch. At least one of the two is required. Member keys don't change.
 */
export async function rotateAccount(
  ports: AccountPorts,
  current: OpenAccount,
  input: { pin?: string; phrase?: string },
): Promise<{ account: OpenAccount }> {
  const { suite, store, deviceKeys } = ports;
  const { accountId } = current;
  // Neither would leave this device as the only way in.
  if (input.pin === undefined && input.phrase === undefined) throw new ConvoyError("MALFORMED_RECORD");

  if (input.phrase !== undefined) {
    // A typo here would leave the account without a working phrase: check it opens today's wrap.
    const wrap = await fetchWrap(ports, { accountId, accountKeyVersion: current.version, method: "recovery" });
    if (!wrap) throw new ConvoyError("RECOVERY_NOT_SET_UP");
    const recoveryKey = deriveRecoveryKey(suite, accountId, input.phrase);
    try {
      suite.wipe(openAccountKeyWrap(wrap, recoveryKey));
    } finally {
      suite.wipe(recoveryKey);
    }
  }

  const next: OpenAccount = { accountId, version: current.version + 1, key: suite.randomBytes(suite.sizes.key) };
  const ops: WriteOp[] = [];

  const wraps = await callPort(() => store.list({ type: "member-keys-wrap", accountId, accountKeyVersion: current.version }));
  for (const json of wraps) {
    const wrap = parseMemberKeysWrap(json, { accountId, accountKeyVersion: current.version });
    const publishedJson = await callPort(() =>
      store.get({ type: "member-keys", teamId: wrap.teamId, accountId, memberKeysVersion: wrap.memberKeysVersion }),
    );
    const published = parseMemberKeys(publishedJson, { teamId: wrap.teamId, accountId, memberKeysVersion: wrap.memberKeysVersion });
    const bundle = openMemberKeysWrap(wrap, current.key, published);
    const context = { accountId, teamId: wrap.teamId, memberKeysVersion: wrap.memberKeysVersion, accountKeyVersion: next.version };
    const rewrapped = createMemberKeysWrap(suite, context, next.key, bundle);
    suite.wipe(bundle.signingSeed, bundle.encryptionSecretKey, bundle.teamStateKey);
    ops.push({ op: "create", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(rewrapped) });
  }

  if (input.pin !== undefined) ops.push(createWrap(await pinWrap(ports, next, input.pin)));
  if (input.phrase !== undefined) ops.push(createWrap(recoveryWrap(ports, next, input.phrase)));
  const device = await callPort(() => deviceKeys.getDevice(accountId));
  if (device) ops.push(createWrap(deviceWrap(ports, next, device)));
  ops.push({ op: "set-account-key-version", accountId, expected: current.version, accountKeyVersion: next.version });

  await commit(ports, ops);
  await callPort(() => deviceKeys.setAccountKeyVersion(accountId, next.version));
  return { account: next };
}
