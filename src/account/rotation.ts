// Rotating the account key (§5.7, D-10, SP-11).
import { ConvoyError } from "../errors.js";
import { callPort, type WriteOp } from "../ports.js";
import { parseMemberKeys } from "../records/member-keys.js";
import {
  bundleKeyPairs,
  createMemberKeysWrap,
  memberKeysWrapToJson,
  openMemberKeysWrap,
  parseMemberKeysWrap,
  type MemberKeyBundle,
} from "../records/member-keys-wrap.js";
import type { MemberBundle } from "../team/context.js";
import { newestTrustedAnchor } from "./recovery.js";
import type { AccountPorts, OpenAccount } from "./context.js";
import { createWrap } from "./context.js";
import { commit, deviceWrap, pinWrap, recoveryWrap, verifyPhrase } from "./unlock-methods.js";

/**
 * Re-wraps every member keys bundle under a new account key version, with the current-device
 * wrap, the recovery wrap (the current phrase is required, and kept unless `newPhrase` replaces
 * it, D-41, D-45), and the PIN wrap if a new PIN is given (else no PIN until one is set, D-40),
 * switched in one atomic batch. Member keys don't change; each team's bundles take the newest
 * trusted anchor as floor, as at a re-key (D-50).
 */
export async function rotateAccount(
  ports: AccountPorts,
  current: OpenAccount,
  input: { phrase: string; newPhrase?: string; newPin?: string },
): Promise<{ account: OpenAccount }> {
  const { suite, store, deviceKeys } = ports;
  const { accountId } = current;
  // An open vault alone can't rotate (D-41): the current phrase proves the account, and is kept.
  if (typeof input?.phrase !== "string") throw new ConvoyError("MALFORMED_RECORD");
  await verifyPhrase(ports, current, input.phrase);

  const next: OpenAccount = { accountId, version: current.version + 1, key: suite.randomBytes(suite.sizes.key) };
  const ops: WriteOp[] = [];

  const wraps = await callPort(() => store.list({ type: "member-keys-wrap", accountId, accountKeyVersion: current.version }));
  const teams = new Map<string, { opened: MemberKeyBundle; held: MemberBundle }[]>();
  for (const json of wraps) {
    const wrap = parseMemberKeysWrap(json, { accountId, accountKeyVersion: current.version });
    const publishedJson = await callPort(() =>
      store.get({ type: "member-keys", teamId: wrap.teamId, accountId, memberKeysVersion: wrap.memberKeysVersion }),
    );
    const published = parseMemberKeys(publishedJson, { teamId: wrap.teamId, accountId, memberKeysVersion: wrap.memberKeysVersion });
    const opened = openMemberKeysWrap(wrap, current.key, published);
    const held = { memberKeysVersion: wrap.memberKeysVersion, published, pairs: bundleKeyPairs(suite, opened), ...(opened.floor ? { floor: opened.floor } : {}) };
    teams.set(wrap.teamId, [...(teams.get(wrap.teamId) ?? []), { opened, held }]);
  }
  for (const [teamId, bundles] of teams) {
    // One floor per team, from every bundle it holds (D-50).
    bundles.sort((a, b) => b.held.memberKeysVersion - a.held.memberKeysVersion);
    const floor = await newestTrustedAnchor(ports, current, teamId, bundles.map((b) => b.held));
    for (const { opened, held } of bundles) {
      const bundle = floor ? { ...opened, floor } : opened;
      const context = { accountId, teamId, memberKeysVersion: held.memberKeysVersion, accountKeyVersion: next.version };
      const rewrapped = createMemberKeysWrap(suite, context, next.key, bundle);
      suite.wipe(bundle.signingSeed, bundle.encryptionSecretKey, bundle.teamStateKey);
      ops.push({ op: "create", key: { type: "member-keys-wrap", ...context }, record: memberKeysWrapToJson(rewrapped) });
    }
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
