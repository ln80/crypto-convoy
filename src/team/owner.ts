// Owner operations (§6.5–§6.9): one object per admin intent, plain data in and out (D-31).
import { encodeInvite } from "../encoding/link.js";
import { ConvoyError, isConvoyError, trustFailure } from "../errors.js";
import { callPort } from "../ports.js";
import { createInvite, inviteToJson, openInviteSecret, parseInvite } from "../records/invite.js";
import { keysHash, parseMemberKeys, type MemberKeys } from "../records/member-keys.js";
import { commitTeam } from "./context.js";
import { checkOwnerRule, listGrants, type Holder } from "./grants.js";
import {
  overviewOf,
  planReconcile,
  type InvitePolicy,
  type KeysHandle,
  type MembershipSnapshot,
  type NeedsHuman,
  type OpenedInvite,
  type ReconcilePlan,
  type TeamOverview,
} from "./membership.js";
import { grantOp, recipientFromKeys, versionOp, type Recipient } from "./rotation.js";
import type { SessionInternals } from "./session.js";

export interface RotationOptions {
  /** Accounts that receive the new version: an allowlist (§6.6). The caller is always kept. */
  readonly keep: readonly string[];
  /** Re-keys approved by this rotation, each pinned to the keys the owner reviewed (§6.8). */
  readonly approveRekeys?: readonly KeysHandle[];
}

export interface ReconcileOptions {
  /**
   * Admit first joiners proven by an invite of the current version (D-32). Off by default: whoever
   * saw the invite link (your server, if it sent it) can make the proof (TH-43). A function decides per joiner.
   */
  readonly autoApproveInvites?: InvitePolicy;
  /** Return the plan without writing anything. */
  readonly dryRun?: boolean;
}

/** What `reconcile` did (or, with `dryRun`, would do), and what it leaves to a human (§6.9). */
export interface ReconcileReport {
  readonly dryRun: boolean;
  /** The version a rotation created (or would create). */
  readonly rotatedTo?: number;
  readonly removed: readonly string[];
  readonly approvedRekeys: readonly string[];
  readonly admitted: readonly string[];
  readonly needsHuman: readonly NeedsHuman[];
}

/** What an approval or removal did: a rotation, grants, or both. */
export interface ChangeReport {
  readonly rotatedTo?: number;
  readonly granted: readonly string[];
}

/**
 * Owner operations on one team. Get it with `team.owner()`; every call checks again that the
 * caller owns the current version (`NOT_AN_OWNER`), so a stale object can't act after a removal.
 */
export class TeamOwner {
  readonly #core: SessionInternals;

  /** @internal Use `team.owner()`. */
  constructor(core: SessionInternals) {
    this.#core = core;
  }

  /** The current team key version. */
  get version(): number {
    return this.#core.current().version;
  }

  /**
   * Each listed or holding account's status, newest keys and their proof, and the warnings
   * that need a human (§6.9). `activeAccountIds` are the accounts the integration considers members.
   */
  async overview(activeAccountIds: readonly string[]): Promise<TeamOverview> {
    this.#core.ownerSigner();
    const snapshot = await this.#snapshot(activeAccountIds);
    try {
      return overviewOf(snapshot);
    } finally {
      this.#forget(snapshot);
    }
  }

  /**
   * Does what needs no human judgement (§6.9, SP-22): rotates out holders no longer active,
   * approves recovery-proven re-keys of members who aren't owners, and admits invite-proven joiners
   * if `autoApproveInvites` allows it. Never widens access otherwise and never changes the owner
   * list. Run it at every owner session. Throws `NOT_AN_OWNER`, `STALE_VERSION` (twice in a row),
   * `TRUST_FAILURE`.
   */
  async reconcile(activeAccountIds: readonly string[], options: ReconcileOptions = {}): Promise<ReconcileReport> {
    for (let attempt = 0; ; attempt++) {
      this.#core.ownerSigner();
      const snapshot = await this.#snapshot(activeAccountIds);
      const plan = planReconcile(snapshot, options.autoApproveInvites);
      this.#forget(snapshot);
      if (options.dryRun) return report(plan, true, plan.rotate ? snapshot.version + 1 : undefined);
      try {
        return await this.#apply(snapshot, plan);
      } catch (error) {
        // Another owner wrote first: reload, plan once more (§6.9).
        if (attempt > 0 || !isConvoyError(error, "STALE_VERSION")) throw error;
        await this.#core.reload();
      }
    }
  }

  /**
   * Approves the keys in `handles` (from `overview`), each pinned to the version reviewed: a
   * re-key of a current holder by one rotation, a joiner by a grant (§6.5, §6.8). Throws
   * `STALE_VERSION` if newer keys were published since, `NOT_AN_OWNER`.
   */
  async approve(handles: readonly KeysHandle[]): Promise<ChangeReport> {
    this.#core.ownerSigner();
    const holding = new Set((await this.#holders()).map((h) => h.accountId));
    const rekeys = handles.filter((h) => holding.has(h.accountId));
    const joins = handles.filter((h) => !holding.has(h.accountId));
    let rotatedTo: number | undefined;
    if (rekeys.length > 0) rotatedTo = (await this.rotate({ keep: [...holding], approveRekeys: rekeys })).version;
    for (const handle of joins) await this.grant(handle);
    return { ...(rotatedTo !== undefined ? { rotatedTo } : {}), granted: handles.map((h) => h.accountId) };
  }

  /** A rotation keeping every holder but `accountIds` (§6.6). Removing an owner is `setOwners`. */
  async remove(accountIds: readonly string[]): Promise<ChangeReport> {
    const keep = (await this.#holders()).map((h) => h.accountId).filter((id) => !accountIds.includes(id));
    const { version, granted } = await this.rotate({ keep });
    return { rotatedTo: version, granted };
  }

  /**
   * Every owner change is a rotation carrying the new owner list (§6.7, D-13). Keeps every
   * current holder unless `keep` says otherwise; new owners must hold the current version.
   */
  async setOwners(owners: readonly string[], options: Partial<RotationOptions> = {}): Promise<{ version: number; granted: string[] }> {
    const keep = options.keep ?? (await this.#holders()).map((h) => h.accountId);
    return this.#rotate({ ...options, keep }, owners);
  }

  /** Accounts whose current access one of `ownerIds` signed: review them before removing those owners (§6.7 step 3). */
  async grantedBy(ownerIds: readonly string[]): Promise<string[]> {
    return [...new Set((await this.#holders()).filter((h) => ownerIds.includes(h.signer.accountId)).map((h) => h.accountId))];
  }

  /**
   * An invite with a join secret (§6.4, D-32): deliver the returned link value in the invite link's
   * fragment, and keep it out of your own UI and logs (TH-43). `inviteeRef` is your reference to
   * the invitee, shown back with the join. Throws `NOT_AN_OWNER`, `STALE_VERSION` (id used).
   */
  async createInvite(inviteId: string, options: { inviteeRef?: string } = {}): Promise<{ invite: string }> {
    const core = this.#core;
    const signer = core.ownerSigner();
    const version = core.writeVersion();
    const { suite } = core.ports;
    const secret = suite.randomBytes(32);
    try {
      const record = createInvite(suite, {
        teamId: core.teamId,
        inviteId,
        teamKeyVersion: version,
        ...(options.inviteeRef !== undefined ? { inviteeRef: options.inviteeRef } : {}),
        teamKey: await core.teamKey(version),
        secret,
        signer: signer.ref,
        signerSecretKey: signer.secretKey,
        createdAt: core.ports.clock.now(),
      });
      await commitTeam(core.ports.store, [{ op: "create", key: { type: "invite", teamId: core.teamId, inviteId }, record: inviteToJson(record) }]);
      return { invite: encodeInvite({ anchor: { version, hash: core.currentHash() }, inviteId, secret }) };
    } finally {
      suite.wipe(secret);
    }
  }

  /**
   * Low level: grants the current version to the reviewed keys, the account's newest (§6.5).
   * Throws `NOT_GRANTED`, `NOT_AN_OWNER`, `STALE_VERSION` (newer keys were published since).
   */
  async grant(handle: KeysHandle, options: { inviteId?: string } = {}): Promise<void> {
    const core = this.#core;
    const signer = core.ownerSigner();
    const keys = await this.#reviewedKeys(handle);
    const version = core.current().version;
    const to = recipientFromKeys(core.ports.suite, keys);
    await commitTeam(core.ports.store, [grantOp(core.ports, core.teamId, version, await core.teamKey(version), to, signer, options.inviteId)]);
  }

  /**
   * Low level: creates the next team key version for the kept accounts (§6.6). Accounts left out
   * lose access to it. Throws `NOT_AN_OWNER`, `STALE_VERSION`, `MALFORMED_RECORD` (over §2 bounds).
   */
  async rotate(options: RotationOptions): Promise<{ version: number; granted: string[] }> {
    return this.#rotate(options, undefined);
  }

  async #apply(snapshot: MembershipSnapshot, plan: ReconcilePlan): Promise<ReconcileReport> {
    let rotatedTo: number | undefined;
    if (plan.rotate) {
      const keep = snapshot.holders.map((h) => h.accountId).filter((id) => !plan.remove.includes(id));
      rotatedTo = (await this.rotate({ keep, approveRekeys: plan.approveRekeys })).version;
    }
    for (const { keys, inviteId } of plan.admit) await this.grant(keys, { inviteId });
    return report(plan, false, rotatedTo);
  }

  /** Invite secrets are wiped once the snapshot was used (best effort). */
  #forget(snapshot: MembershipSnapshot): void {
    for (const invite of snapshot.invites.values()) this.#core.ports.suite.wipe(invite.secret);
  }

  #holders(): Promise<Holder[]> {
    return this.#core.holdersOf(this.#core.current().version);
  }

  /** Every published `member-keys` record of the team, by account, ascending versions. */
  async #allKeys(): Promise<Map<string, MemberKeys[]>> {
    const { ports, teamId } = this.#core;
    const jsons = await callPort(() => ports.store.list({ type: "member-keys", teamId }));
    const byAccount = new Map<string, MemberKeys[]>();
    for (const json of jsons) {
      const keys = parseMemberKeys(json, { teamId, accountId: (json as { accountId: string }).accountId });
      byAccount.set(keys.accountId, [...(byAccount.get(keys.accountId) ?? []), keys]);
    }
    for (const list of byAccount.values()) list.sort((a, b) => a.memberKeysVersion - b.memberKeysVersion);
    return byAccount;
  }

  async #publishedKeys(accountId: string): Promise<MemberKeys[]> {
    const { ports, teamId } = this.#core;
    const jsons = await callPort(() => ports.store.list({ type: "member-keys", teamId, accountId }));
    return jsons.map((json) => parseMemberKeys(json, { teamId, accountId })).sort((a, b) => a.memberKeysVersion - b.memberKeysVersion);
  }

  /**
   * The keys an owner reviewed, if they are still the account's newest: keys published after the
   * review, or replaced ones, are never approved (§6.5, §6.8). Throws `NOT_GRANTED`, `STALE_VERSION`.
   */
  async #reviewedKeys(handle: KeysHandle): Promise<MemberKeys> {
    const newest = (await this.#publishedKeys(handle.accountId)).at(-1);
    if (!newest) throw new ConvoyError("NOT_GRANTED");
    if (newest.memberKeysVersion !== handle.memberKeysVersion) throw new ConvoyError("STALE_VERSION");
    return newest;
  }

  async #snapshot(activeAccountIds: readonly string[]): Promise<MembershipSnapshot> {
    const core = this.#core;
    const current = core.current();
    const holders = await this.#holders();
    const keys = await this.#allKeys();
    const holding = new Set(holders.map((h) => h.accountId));

    // Accounts with keys but no current access: did they hold an older version (outdated) or never (§6.9)?
    const heldBefore = new Set<string>();
    const unresolved: string[] = [];
    for (const accountId of keys.keys()) {
      if (holding.has(accountId)) continue;
      const grants = await listGrants(core.ports, core.teamId, { accountId });
      if (grants.some((g) => g.teamKeyVersion < current.version)) heldBefore.add(accountId);
      else unresolved.push(accountId);
    }
    if (unresolved.length > 0) {
      // Older rosters may lie below the loaded chain: reach version 1, pinned by hash (§6.2).
      const chain = await core.chainFrom(1);
      for (const accountId of unresolved) {
        if (chain.records.some((r) => r.version < current.version && r.roster.some((e) => e.accountId === accountId))) heldBefore.add(accountId);
      }
    }

    const wanted = new Set([...keys.values()].flatMap((list) => (list.at(-1)?.inviteProof ? [list.at(-1)!.inviteProof!.inviteId] : [])));
    return {
      version: current.version,
      owners: current.owners.map((o) => o.accountId),
      self: core.accountId,
      holders,
      keys,
      heldBefore,
      invites: wanted.size > 0 ? await this.#openInvites(wanted) : new Map(),
      active: new Set(activeAccountIds),
    };
  }

  /** The invites joiners name, opened. One that fails its checks is ignored: it proves nothing (§6.9). */
  async #openInvites(wanted: ReadonlySet<string>): Promise<Map<string, OpenedInvite>> {
    const { ports, teamId } = this.#core;
    const opened = new Map<string, OpenedInvite>();
    for (const json of await callPort(() => ports.store.list({ type: "invite", teamId }))) {
      const inviteId = (json as { inviteId?: unknown }).inviteId;
      if (typeof inviteId !== "string" || !wanted.has(inviteId)) continue;
      try {
        const invite = parseInvite(json, { teamId, inviteId });
        checkOwnerRule(invite, await this.#core.chainFrom(invite.teamKeyVersion));
        const secret = openInviteSecret(invite, await this.#core.teamKey(invite.teamKeyVersion));
        opened.set(inviteId, {
          inviteId,
          teamKeyVersion: invite.teamKeyVersion,
          ...(invite.inviteeRef !== undefined ? { inviteeRef: invite.inviteeRef } : {}),
          secret,
        });
      } catch (error) {
        if (!(error instanceof ConvoyError) || isConvoyError(error, "STORE_ERROR")) throw error;
      }
    }
    return opened;
  }

  /** One set of keys per account: approved newest keys, or the keys it holds (§6.6 step 2). */
  async #recipients(holders: readonly Holder[], options: RotationOptions): Promise<Recipient[]> {
    const { suite } = this.#core.ports;
    const newest = new Map<string, Holder>();
    for (const h of holders) {
      const seen = newest.get(h.accountId);
      if (!seen || h.memberKeysVersion > seen.memberKeysVersion) newest.set(h.accountId, h);
    }
    const recipients: Recipient[] = [];
    for (const [accountId, holder] of newest) {
      const approval = options.approveRekeys?.find((a) => a.accountId === accountId);
      if (approval) {
        recipients.push(recipientFromKeys(suite, await this.#reviewedKeys(approval)));
        continue;
      }
      // The keys held, resolved from their published record and checked against the pinned hash.
      const keys = (await this.#publishedKeys(accountId)).find((k) => k.memberKeysVersion === holder.memberKeysVersion);
      if (!keys || !suite.equal(keysHash(suite, keys), holder.keysHash)) throw this.#core.markUnverified(trustFailure("key_mismatch"));
      recipients.push(recipientFromKeys(suite, keys));
    }
    return recipients;
  }

  async #rotate(options: RotationOptions, newOwners: readonly string[] | undefined): Promise<{ version: number; granted: string[] }> {
    const core = this.#core;
    const signer = core.ownerSigner();
    const current = core.current();
    const kept = (await this.#holders()).filter((h) => h.accountId === core.accountId || options.keep.includes(h.accountId));
    const recipients = await this.#recipients(kept, options);

    const { suite } = core.ports;
    const nextKey = suite.randomBytes(suite.sizes.key);
    const currentKey = await core.teamKey(current.version);
    const owners = newOwners ?? current.owners.map((o) => o.accountId);
    try {
      const version = versionOp(core.ports, current, core.currentHash(), currentKey, nextKey, owners, recipients, signer);
      // One record, roster included: a rotation is never half done (§6.6 step 5, D-34).
      await commitTeam(core.ports.store, [version]);
    } finally {
      suite.wipe(nextKey);
    }
    await core.reload();
    return { version: current.version + 1, granted: recipients.map((r) => r.accountId) };
  }
}

function report(plan: ReconcilePlan, dryRun: boolean, rotatedTo: number | undefined): ReconcileReport {
  return {
    dryRun,
    ...(rotatedTo !== undefined ? { rotatedTo } : {}),
    removed: [...plan.remove],
    approvedRekeys: plan.approveRekeys.map((h) => h.accountId),
    admitted: plan.admit.map((a) => a.keys.accountId),
    needsHuman: [...plan.needsHuman],
  };
}
