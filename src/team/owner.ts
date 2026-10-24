// Owner operations (§6.5–§6.9): one object per admin intent, plain data in and out (D-31).
// Every access change is a rotation whose roster lists the recipients (D-37).
import { toBase64url } from "../encoding/base64url.js";
import { ConvoyError, isConvoyError, trustFailure } from "../errors.js";
import { callPort } from "../ports.js";
import { keysHash, parseMemberKeys, type MemberKeys } from "../records/member-keys.js";
import type { Holder } from "./access.js";
import { commitTeam } from "./context.js";
import {
  overviewOf,
  planReconcile,
  type KeysHandle,
  type MembershipSnapshot,
  type NeedsHuman,
  type ReconcilePlan,
  type TeamOverview,
} from "./membership.js";
import { recipientFromKeys, versionOp, type Recipient } from "./rotation.js";
import type { SessionInternals } from "./session.js";

export interface RotationOptions {
  /** Holders of the current version that receive the new one: an allowlist (§6.6). The caller is always kept. */
  readonly keep: readonly string[];
  /**
   * Keys approved by this rotation, each pinned to the version the owner reviewed (§6.5, §6.8):
   * a holder's new keys replace its old ones; an account that holds nothing is added.
   */
  readonly approve?: readonly KeysHandle[];
}

export interface ReconcileOptions {
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
  readonly needsHuman: readonly NeedsHuman[];
}

/** What an approval or a removal did: the rotation it made and the keys it approved. */
export interface ChangeReport {
  readonly rotatedTo: number;
  readonly approved: readonly string[];
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
    return overviewOf(await this.#snapshot(activeAccountIds));
  }

  /**
   * Does what needs no human judgement (§6.9, SP-22): rotates out holders no longer active
   * (never owners), and approves recovery-proven re-keys of members who aren't owners. Never
   * widens access otherwise and never changes the owner list. Run it at every owner session.
   * Throws `NOT_AN_OWNER`, `STALE_VERSION` (twice in a row), `TRUST_FAILURE`.
   */
  async reconcile(activeAccountIds: readonly string[], options: ReconcileOptions = {}): Promise<ReconcileReport> {
    for (let attempt = 0; ; attempt++) {
      this.#core.ownerSigner();
      const snapshot = await this.#snapshot(activeAccountIds);
      const plan = planReconcile(snapshot);
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
   * Approves the keys in `handles` (from `overview`), each pinned to the version reviewed, in one
   * rotation keeping every holder (§6.5, §6.8): joiners are added, re-keyed holders get their new
   * keys. Throws `STALE_VERSION` if newer keys were published since, `NOT_AN_OWNER`.
   */
  async approve(handles: readonly KeysHandle[]): Promise<ChangeReport> {
    const keep = (await this.#holders()).map((h) => h.accountId);
    const { version } = await this.rotate({ keep, approve: handles });
    return { rotatedTo: version, approved: handles.map((h) => h.accountId) };
  }

  /** A rotation keeping every holder but `accountIds` (§6.6). Removing an owner is `setOwners`. */
  async remove(accountIds: readonly string[]): Promise<ChangeReport> {
    const keep = (await this.#holders()).map((h) => h.accountId).filter((id) => !accountIds.includes(id));
    const { version } = await this.rotate({ keep });
    return { rotatedTo: version, approved: [] };
  }

  /**
   * Every owner change is a rotation carrying the new owner list (§6.7, D-13). Keeps every
   * current holder unless `keep` says otherwise; new owners must hold the current version.
   */
  async setOwners(owners: readonly string[], options: Partial<RotationOptions> = {}): Promise<{ version: number; recipients: string[] }> {
    const keep = options.keep ?? (await this.#holders()).map((h) => h.accountId);
    return this.#rotate({ ...options, keep }, owners);
  }

  /** Accounts in the current roster that one of `ownerIds` signed: review them before removing those owners (§6.7 step 3). */
  async grantedBy(ownerIds: readonly string[]): Promise<string[]> {
    return [...new Set((await this.#holders()).filter((h) => ownerIds.includes(h.signer.accountId)).map((h) => h.accountId))];
  }

  /**
   * Low level: creates the next team key version for the kept holders and the approved keys
   * (§6.6). Accounts left out lose access to it. Throws `NOT_AN_OWNER`, `STALE_VERSION`,
   * `MALFORMED_RECORD` (over the §2 bounds).
   */
  async rotate(options: RotationOptions): Promise<{ version: number; recipients: string[] }> {
    return this.#rotate(options, undefined);
  }

  async #apply(snapshot: MembershipSnapshot, plan: ReconcilePlan): Promise<ReconcileReport> {
    let rotatedTo: number | undefined;
    if (plan.rotate) {
      const keep = snapshot.holders.map((h) => h.accountId).filter((id) => !plan.remove.includes(id));
      rotatedTo = (await this.rotate({ keep, approve: plan.approveRekeys })).version;
    }
    return report(plan, false, rotatedTo);
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
    for (const list of byAccount.values()) this.#ascending(list);
    return byAccount;
  }

  async #publishedKeys(accountId: string): Promise<MemberKeys[]> {
    const { ports, teamId } = this.#core;
    const jsons = await callPort(() => ports.store.list({ type: "member-keys", teamId, accountId }));
    return this.#ascending(jsons.map((json) => parseMemberKeys(json, { teamId, accountId })));
  }

  /** Sorts by version; two records for one version are the server's equivocation (D-55). Throws `TRUST_FAILURE`. */
  #ascending(list: MemberKeys[]): MemberKeys[] {
    list.sort((a, b) => a.memberKeysVersion - b.memberKeysVersion);
    if (list.some((k, i) => i > 0 && k.memberKeysVersion === list[i - 1]!.memberKeysVersion)) throw this.#core.markUnverified(trustFailure("key_mismatch"));
    return list;
  }

  /**
   * The keys an owner reviewed, if they are still the account's newest with the reviewed keys hash:
   * keys published after the review, or replaced ones, are never approved (§6.5, §6.8, D-55).
   * Throws `NOT_GRANTED`, `STALE_VERSION`, `TRUST_FAILURE` (another record for the reviewed version).
   */
  async #reviewedKeys(handle: KeysHandle): Promise<MemberKeys> {
    const newest = (await this.#publishedKeys(handle.accountId)).at(-1);
    if (!newest) throw new ConvoyError("NOT_GRANTED");
    if (newest.memberKeysVersion !== handle.memberKeysVersion) throw new ConvoyError("STALE_VERSION");
    if (toBase64url(keysHash(newest.suite, newest)) !== handle.keysHash) throw this.#core.markUnverified(trustFailure("key_mismatch"));
    return newest;
  }

  async #snapshot(activeAccountIds: readonly string[]): Promise<MembershipSnapshot> {
    const core = this.#core;
    const current = core.current();
    const holders = await this.#holders();
    const keys = await this.#allKeys();
    const holding = new Set(holders.map((h) => h.accountId));
    // The held keys are the ones the roster pins: a proof is checked against their recovery key (§4.2),
    // so a record the server serves for a held version must have the roster's keys hash.
    const { suite } = core.ports;
    for (const holder of holders) {
      const record = keys.get(holder.accountId)?.find((k) => k.memberKeysVersion === holder.memberKeysVersion);
      if (record && !suite.equal(keysHash(suite, record), holder.keysHash)) throw core.markUnverified(trustFailure("key_mismatch"));
    }

    // Accounts with keys but no current access: did they hold an older version (outdated) or never (§6.9)?
    const heldBefore = new Set<string>();
    const inRoster = (records: readonly { version: number; roster: readonly { accountId: string }[] }[], accountId: string) =>
      records.some((r) => r.version < current.version && r.roster.some((e) => e.accountId === accountId));
    let chain = await core.chainFrom(current.version);
    const candidates = [...keys.keys()].filter((id) => !holding.has(id));
    for (const id of candidates) if (inRoster(chain.records, id)) heldBefore.add(id);
    const unresolved = candidates.filter((id) => !heldBefore.has(id));
    if (unresolved.length > 0 && chain.records[0]!.version > 1) {
      // Older rosters may lie below the loaded chain: reach version 1, pinned by hash (§6.2).
      chain = await core.chainFrom(1);
      for (const id of unresolved) if (inRoster(chain.records, id)) heldBefore.add(id);
    }

    // Keys the caller holds: the same version and keys hash as the published record (§4.3, D-47).
    const selfHeld = new Set(
      core
        .ownKeys()
        .filter((own) => keys.get(core.accountId)?.some((k) => k.memberKeysVersion === own.memberKeysVersion && suite.equal(keysHash(suite, k), keysHash(suite, own))))
        .map((own) => own.memberKeysVersion),
    );

    return {
      version: current.version,
      owners: current.owners.map((o) => o.accountId),
      self: core.accountId,
      selfHeld,
      holders,
      keys,
      heldBefore,
      active: new Set(activeAccountIds),
    };
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
      if (options.approve?.some((a) => a.accountId === accountId)) continue;
      // The keys held, resolved from their published record and checked against the pinned hash.
      const keys = (await this.#publishedKeys(accountId)).find((k) => k.memberKeysVersion === holder.memberKeysVersion);
      if (!keys || !suite.equal(keysHash(suite, keys), holder.keysHash)) throw this.#core.markUnverified(trustFailure("key_mismatch"));
      recipients.push(recipientFromKeys(suite, keys));
    }
    // Approved keys: a holder's replacement, or a new member (§6.5).
    for (const handle of options.approve ?? []) recipients.push(recipientFromKeys(suite, await this.#reviewedKeys(handle)));
    return recipients;
  }

  async #rotate(options: RotationOptions, newOwners: readonly string[] | undefined): Promise<{ version: number; recipients: string[] }> {
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
    return { version: current.version + 1, recipients: recipients.map((r) => r.accountId) };
  }
}

function report(plan: ReconcilePlan, dryRun: boolean, rotatedTo: number | undefined): ReconcileReport {
  return {
    dryRun,
    ...(rotatedTo !== undefined ? { rotatedTo } : {}),
    removed: [...plan.remove],
    approvedRekeys: plan.approveRekeys.map((h) => h.accountId),
    needsHuman: [...plan.needsHuman],
  };
}
