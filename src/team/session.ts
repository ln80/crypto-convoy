// The team session (§6, §9): one team's keys, never the account key (D-03, SP-02).
import { encodeAnchor, type Anchor } from "../encoding/link.js";
import { ConvoyError, isConvoyError, trustFailure } from "../errors.js";
import { callPort } from "../ports.js";
import type { Grant } from "../records/grant.js";
import { hasValidContinuity, keysHash, parseMemberKeys, type MemberKeys } from "../records/member-keys.js";
import { openPreviousKey, type TeamKeyVersion } from "../records/team-key-version.js";
import { fetchInbox, openSubmissionRecord, storeInbox } from "../content/inbox.js";
import { newItemDraft, openedItem, type ItemDraft } from "../content/items.js";
import type { OpenedItem, OpenedSubmission } from "../content/opened.js";
import { encodeLinkKey } from "../encoding/link.js";
import { itemToJson, openItemKey, parseItem, sealItem, type Item } from "../records/item.js";
import { advanceAnchor } from "./anchors.js";
import { chainFrom, loadChain } from "./load.js";
import { isOwner, type OwnerChange, type VerifiedChain } from "./chain.js";
import { commitTeam, type MemberBundle, type TeamPorts } from "./context.js";
import { checkOwnerRule, holdersOf, listGrants, openOwnAccess, type Holder, type OwnAccess } from "./grants.js";
import { grantOp, recipientFromKeys, versionOp, type Recipient, type Signer } from "./rotation.js";

/** What this account can do in the team (§9). */
export type AccessState = "not-joined" | "pending" | "ready" | "unverified";

/** A member holding the current version, and who gave it to them (SP-15). */
export interface Member {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly grantedBy: string;
}

/** A member's published keys, for the owner to confirm before granting (§6.5, §6.8). */
export interface MemberRequest {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  /** `new`: first keys. `routine`: signed by the previous keys. `unproven`: replaced without that proof — verify out of band. */
  readonly continuity: "new" | "routine" | "unproven";
  /** Whether these exact keys already hold the current version. */
  readonly granted: boolean;
}

/** One account's access, as an owner sees it (§12). */
export type MemberStatus =
  | { readonly accountId: string; readonly status: "no-keys" | "approved" }
  | {
      readonly accountId: string;
      readonly status: "awaiting-approval" | "outdated" | "rekey-awaiting-approval";
      /** `routine`: the previous keys vouch for these; `unproven`: verify out of band (§6.8). */
      readonly continuity: MemberRequest["continuity"];
    };

/** Something an owner should act on, with the operation that clears it (§12). */
export interface Warning {
  readonly code: "single-owner" | "members-awaiting-approval" | "rekeys-awaiting-approval" | "rotation-needed";
  readonly accountIds: readonly string[];
  readonly action: "setOwners" | "grant" | "rotate";
}

/** Keys an owner reviewed: the approval holds for exactly this version (§6.8). */
export interface KeysHandle {
  readonly accountId: string;
  readonly memberKeysVersion: number;
}

export interface RotationOptions {
  /** Accounts that receive the new version: an allowlist (§6.6). The caller is always kept. */
  readonly keep: readonly string[];
  /** Re-keys approved by this rotation, each pinned to the keys the owner reviewed (§6.8). */
  readonly approveRekeys?: readonly KeysHandle[];
}

/** Library-only access to a session's keys and ports. Never exported from the package entry (D-15). */
export interface SessionInternals {
  teamKey(version: number): Promise<Uint8Array>;
  writeVersion(): number;
  readonly ports: TeamPorts;
}

const INTERNALS = new WeakMap<TeamSession, SessionInternals>();

export function sessionInternals(session: TeamSession): SessionInternals {
  return INTERNALS.get(session)!;
}

function continuityOf(newest: MemberKeys, keys: readonly MemberKeys[]): MemberRequest["continuity"] {
  if (newest.memberKeysVersion === 1) return "new";
  const previous = keys.find((k) => k.memberKeysVersion === newest.memberKeysVersion - 1);
  return previous && hasValidContinuity(newest, previous) ? "routine" : "unproven";
}

export class TeamSession {
  readonly teamId: string;
  readonly accountId: string;
  readonly #ports: TeamPorts;
  readonly #bundles: readonly MemberBundle[];
  readonly #invite: Anchor | undefined;
  #state: AccessState = "not-joined";
  #failure: ConvoyError | undefined;
  #chain: VerifiedChain | undefined;
  #own: OwnAccess | undefined;
  #keys = new Map<number, Uint8Array>();
  #ownerChanges: OwnerChange[] = [];

  private constructor(ports: TeamPorts, accountId: string, teamId: string, bundles: readonly MemberBundle[], invite?: Anchor) {
    this.#ports = ports;
    this.accountId = accountId;
    this.teamId = teamId;
    this.#bundles = bundles;
    this.#invite = invite;
    INTERNALS.set(this, { teamKey: (v) => this.#teamKey(v), writeVersion: () => this.#writeVersion(), ports });
  }

  /** @internal Built by the vault, which hands over only this team's keys (§5.8). */
  static async open(ports: TeamPorts, accountId: string, teamId: string, bundles: readonly MemberBundle[], invite?: Anchor) {
    const session = new TeamSession(ports, accountId, teamId, bundles, invite);
    await session.#load();
    return session;
  }

  /** @internal A session for a team whose member keys failed a trust check while opening. */
  static failed(ports: TeamPorts, accountId: string, teamId: string, failure: ConvoyError): TeamSession {
    const session = new TeamSession(ports, accountId, teamId, []);
    session.#markUnverified(failure);
    return session;
  }

  get state(): AccessState {
    return this.#state;
  }

  /** The trust failure that made the session `unverified`, if any. */
  get failure(): ConvoyError | undefined {
    return this.#failure;
  }

  /** The newest verified team key version (0 before any is known). */
  get currentVersion(): number {
    return this.#current?.version ?? 0;
  }

  /** Owner list changes since this account's last verified state (SP-15). */
  get ownerChanges(): readonly OwnerChange[] {
    return this.#ownerChanges;
  }

  /** The owners of the current version. */
  owners(): string[] {
    return this.#requireChain().records.at(-1)!.owners.map((o) => o.accountId);
  }

  /** The anchor to put in an invite link's fragment (§6.4). */
  inviteAnchor(): string {
    const chain = this.#requireChain();
    const version = this.currentVersion;
    return encodeAnchor({ version, hash: chain.hashes.get(version)! });
  }

  /** Holders of the current version (its roster, then grants since), each with who gave it (§6.5, SP-15). Throws `TRUST_FAILURE`. */
  async members(): Promise<Member[]> {
    const holders = await this.#currentHolders();
    return holders.map((h) => ({ accountId: h.accountId, memberKeysVersion: h.memberKeysVersion, grantedBy: h.signer.accountId }));
  }

  /** Members whose current access was signed by one of `accountIds`: review them before removing those owners (§6.7 step 3). */
  async grantedBy(accountIds: readonly string[]): Promise<string[]> {
    return (await this.members()).filter((m) => accountIds.includes(m.grantedBy)).map((m) => m.accountId);
  }

  /** Whether an account holding the current version is no longer active (§6.6, TH-14). */
  async needsRotation(activeAccountIds: readonly string[]): Promise<boolean> {
    return (await this.members()).some((m) => !activeAccountIds.includes(m.accountId));
  }

  /** A member's newest published keys and whether a previous key vouches for them (§6.8 step 2). */
  async memberRequest(accountId: string): Promise<MemberRequest> {
    this.#requireUsable();
    const keys = await this.#publishedKeys(accountId);
    const newest = keys.at(-1);
    if (!newest) throw new ConvoyError("NOT_GRANTED");
    const continuity = continuityOf(newest, keys);
    const granted = (await this.#currentHolders()).some(
      (h) => h.accountId === accountId && h.memberKeysVersion === newest.memberKeysVersion,
    );
    return { accountId, memberKeysVersion: newest.memberKeysVersion, continuity, granted };
  }

  /**
   * Grants the current version to the keys the owner confirmed (§6.5): the account's newest
   * published keys only. The caller must be an owner. Throws `NOT_GRANTED`, `TRUST_FAILURE`
   * (`not_an_owner`), `STALE_VERSION` (newer keys were published since).
   */
  async grant(accountId: string, memberKeysVersion: number): Promise<void> {
    const signer = this.#ownerSigner();
    const keys = await this.#reviewedKeys({ accountId, memberKeysVersion });
    const teamKey = await this.#teamKey(this.currentVersion);
    const to = recipientFromKeys(this.#ports.suite, keys);
    await commitTeam(this.#ports.store, [grantOp(this.#ports, this.teamId, this.currentVersion, teamKey, to, signer)]);
  }

  /**
   * Creates the next team key version for the kept accounts (§6.6). Accounts left out lose access
   * to it. Throws `NOT_GRANTED`, `TRUST_FAILURE` (`not_an_owner`), `STALE_VERSION`.
   */
  async rotate(options: RotationOptions): Promise<{ version: number; granted: string[] }> {
    return this.#rotate(options, undefined);
  }

  /** Every owner change is a rotation carrying the new owner list (§6.7, D-13). */
  async setOwners(owners: readonly string[], options: RotationOptions): Promise<{ version: number; granted: string[] }> {
    return this.#rotate(options, owners);
  }

  /**
   * Starts an item (§7.1, D-27): add parts, store their ciphertext yourself, then `seal(itemId)`
   * stores the `item` record at the version current then. Throws `NOT_GRANTED`; `seal` throws
   * `NOT_GRANTED` or `STALE_VERSION` (id used, version changed while sealing).
   */
  beginItem(): ItemDraft {
    this.#writeVersion();
    return newItemDraft(this.#ports, async (itemKey, manifest, itemId) => {
      const version = this.#writeVersion();
      const record = sealItem(
        this.#ports.suite,
        { teamId: this.teamId, itemId, teamKeyVersion: version, createdBy: this.accountId, createdAt: this.#ports.clock.now() },
        await this.#teamKey(version),
        itemKey,
        manifest,
      );
      await commitTeam(this.#ports.store, [{ op: "create", key: { type: "item", teamId: this.teamId, itemId }, record: itemToJson(record) }]);
    });
  }

  /**
   * Opens an item's key record from the key store (§7.2); parts are then opened on demand with
   * the ciphertext you fetch. Throws `NOT_GRANTED`, `DECRYPTION_FAILED`, `STORE_ERROR` (no record).
   */
  async openItem(itemId: string): Promise<OpenedItem> {
    const record = await this.#fetchItem(itemId);
    return openedItem(this.#ports, record, await this.#itemKey(record));
  }

  /** The item key for a share link's fragment (§7.3). Whoever holds the link can read the item (TH-23). */
  async shareLinkKey(itemId: string): Promise<string> {
    const key = await this.#itemKey(await this.#fetchItem(itemId));
    try {
      return encodeLinkKey(key);
    } finally {
      this.#ports.suite.wipe(key);
    }
  }

  /** Creates an inbox at the current version; the link key goes in the inbox link's fragment (§7.4). */
  async createInbox(inboxId: string): Promise<{ linkKey: string }> {
    const version = this.#writeVersion();
    return storeInbox(this.#ports, this.#ports.store, { teamId: this.teamId, inboxId, teamKeyVersion: version, createdBy: this.accountId }, await this.#teamKey(version));
  }

  /**
   * A new key pair under the current version, with a new link (§7.4, D-20). Ends a removed
   * member's access to new submissions once the integration retires `inboxId`'s link.
   */
  async replaceInbox(inboxId: string, newInboxId: string): Promise<{ linkKey: string }> {
    await fetchInbox(this.#ports.store, this.teamId, inboxId);
    return this.createInbox(newInboxId);
  }

  /**
   * Opens a submission record the integration stored (§7.6); parts are then opened on demand.
   * Throws `NOT_GRANTED`, `DECRYPTION_FAILED`, `TRUST_FAILURE` (`context_mismatch`, `key_mismatch`).
   */
  async openSubmission(inboxId: string, submissionId: string, submissionRecord: unknown): Promise<OpenedSubmission> {
    const inbox = await fetchInbox(this.#ports.store, this.teamId, inboxId);
    return openSubmissionRecord(this.#ports, inbox, await this.#teamKey(inbox.teamKeyVersion), submissionId, submissionRecord);
  }

  /**
   * Each account's access, for an owner's member list (§12, SP-15): `no-keys` (hasn't set up or
   * joined), `awaiting-approval`, `approved`, `outdated` (only older versions granted), or
   * `rekey-awaiting-approval` (newer keys published, with their continuity hint).
   */
  async memberStatuses(accountIds: readonly string[]): Promise<MemberStatus[]> {
    const current = await this.#currentHolders();
    const statuses: MemberStatus[] = [];
    for (const accountId of accountIds) {
      const keys = await this.#publishedKeys(accountId);
      const newest = keys.at(-1);
      const granted = current.filter((g) => g.accountId === accountId).map((g) => g.memberKeysVersion);
      if (!newest) {
        statuses.push({ accountId, status: "no-keys" });
      } else if (granted.includes(newest.memberKeysVersion)) {
        statuses.push({ accountId, status: "approved" });
      } else if (granted.length > 0) {
        statuses.push({ accountId, status: "rekey-awaiting-approval", continuity: continuityOf(newest, keys) });
      } else {
        const older = await this.#heldBefore(accountId);
        statuses.push({ accountId, status: older ? "outdated" : "awaiting-approval", continuity: continuityOf(newest, keys) });
      }
    }
    return statuses;
  }

  /**
   * What needs an owner's attention (§12, SP-15), each with the operation that clears it.
   * `activeAccountIds` are the accounts the integration considers members now.
   */
  async warnings(activeAccountIds: readonly string[]): Promise<Warning[]> {
    const warnings: Warning[] = [];
    if (this.owners().length === 1) warnings.push({ code: "single-owner", accountIds: this.owners(), action: "setOwners" });
    const statuses = await this.memberStatuses(activeAccountIds);
    const waiting = statuses.filter((s) => s.status === "awaiting-approval" || s.status === "outdated").map((s) => s.accountId);
    if (waiting.length > 0) warnings.push({ code: "members-awaiting-approval", accountIds: waiting, action: "grant" });
    const rekeys = statuses.filter((s) => s.status === "rekey-awaiting-approval").map((s) => s.accountId);
    if (rekeys.length > 0) warnings.push({ code: "rekeys-awaiting-approval", accountIds: rekeys, action: "rotate" });
    const granted = (await this.members()).map((m) => m.accountId);
    const inactive = [...new Set(granted.filter((id) => !activeAccountIds.includes(id)))];
    if (inactive.length > 0) warnings.push({ code: "rotation-needed", accountIds: inactive, action: "rotate" });
    return warnings;
  }

  async #fetchItem(itemId: string): Promise<Item> {
    const json = await callPort(() => this.#ports.store.get({ type: "item", teamId: this.teamId, itemId }));
    if (json === null || json === undefined) throw new ConvoyError("STORE_ERROR");
    return parseItem(json, { teamId: this.teamId, itemId });
  }

  /** Whether the account held a version before the current one: a grant, or a roster entry of the loaded chain. */
  async #heldBefore(accountId: string): Promise<boolean> {
    return this.#guard(async () => {
      const grants = await listGrants(this.#ports, this.teamId, { accountId });
      const chain = await this.#chainFrom(Math.min(...grants.map((g) => g.teamKeyVersion)));
      for (const grant of grants) checkOwnerRule(grant, chain);
      const older = (v: number) => v < this.currentVersion;
      return grants.some((g) => older(g.teamKeyVersion)) || chain.records.some((r) => older(r.version) && r.roster.some((e) => e.accountId === accountId));
    });
  }

  async #itemKey(record: Item): Promise<Uint8Array> {
    return openItemKey(record, await this.#teamKey(record.teamKeyVersion));
  }

  /** The key of `version`, opened through the chain from the granted version (§6.2). Throws `NOT_GRANTED` above it. */
  async #teamKey(version: number): Promise<Uint8Array> {
    this.#requireUsable();
    const own = this.#own;
    if (!own || version > own.teamKeyVersion || version < 1) throw new ConvoyError("NOT_GRANTED");
    await this.#guard(() => this.#chainFrom(version));
    for (let k = own.teamKeyVersion; k > version; k--) {
      if (!this.#keys.has(k - 1)) this.#keys.set(k - 1, openPreviousKey(this.#record(k), this.#keys.get(k)!));
    }
    return this.#keys.get(version)!;
  }

  /** Writes need the current version (§7.1). Throws `NOT_GRANTED`. */
  #writeVersion(): number {
    this.#requireUsable();
    if (this.#state !== "ready") throw new ConvoyError("NOT_GRANTED");
    return this.currentVersion;
  }

  /** Forgets this team's keys (best effort). */
  close(): void {
    for (const key of this.#keys.values()) this.#ports.suite.wipe(key);
    this.#keys.clear();
  }

  get #current(): TeamKeyVersion | undefined {
    return this.#chain?.records.at(-1);
  }

  #record(version: number): TeamKeyVersion {
    return this.#requireChain().records.find((r) => r.version === version)!;
  }

  async #load(): Promise<void> {
    if (this.#bundles.length === 0) {
      this.#state = "not-joined";
      return;
    }
    try {
      await this.#verify();
    } catch (error) {
      if (!isConvoyError(error, "TRUST_FAILURE")) throw error;
      this.#markUnverified(error);
    }
  }

  async #verify(): Promise<void> {
    const { chain, server } = await loadChain(this.#ports, this.accountId, this.teamId, this.#bundles, this.#invite);
    const own = await openOwnAccess(this.#ports, this.teamId, this.accountId, chain, (v) => chainFrom(this.#ports, this.teamId, chain, v), this.#bundles);

    this.#chain = own?.chain ?? chain;
    this.#ownerChanges = [...chain.ownerChanges];
    this.close();
    this.#own = own ?? undefined;
    if (own) this.#keys.set(own.teamKeyVersion, own.teamKey);
    this.#state = own && own.teamKeyVersion === this.currentVersion ? "ready" : "pending";
    await advanceAnchor(this.#ports, this.accountId, this.teamId, chain, this.#bundles[0]!, server);
  }

  #markUnverified(error: ConvoyError): ConvoyError {
    // Sticky for the session: tampering or a bug, never retried automatically (§9).
    this.#state = "unverified";
    this.#failure = error;
    this.close();
    return error;
  }

  #requireUsable() {
    if (this.#state === "unverified") throw this.#failure!;
  }

  #requireChain(): VerifiedChain {
    this.#requireUsable();
    if (!this.#chain) throw new ConvoyError("NOT_GRANTED");
    return this.#chain;
  }

  /** The caller's keys listed among the current owners; their own grant must be current. */
  #ownerSigner(): Signer {
    this.#writeVersion();
    const current = this.#current!;
    for (const bundle of this.#bundles) {
      const ref = { accountId: this.accountId, signingPublicKey: bundle.pairs.signing.publicKey };
      if (isOwner(current, ref)) return { ref, secretKey: bundle.pairs.signing.secretKey };
    }
    throw trustFailure("not_an_owner");
  }

  /** The verified chain reaching down to `version` (older records are fetched on demand). Throws `TRUST_FAILURE`. */
  async #chainFrom(version: number): Promise<VerifiedChain> {
    const chain = await chainFrom(this.#ports, this.teamId, this.#requireChain(), version);
    this.#chain = chain;
    return chain;
  }

  async #guard<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error) {
      if (isConvoyError(error, "TRUST_FAILURE")) this.#markUnverified(error);
      throw error;
    }
  }

  /** Who holds `version`: its roster and its grants, owner rule checked (§6.5). Throws `TRUST_FAILURE`. */
  async #holdersOf(version: number): Promise<Holder[]> {
    return this.#guard(async () => {
      const chain = await this.#chainFrom(version);
      const grants = await listGrants(this.#ports, this.teamId, { teamKeyVersion: version });
      return holdersOf(this.#record(version), grants, chain);
    });
  }

  #currentHolders(): Promise<Holder[]> {
    return this.#holdersOf(this.currentVersion);
  }

  async #publishedKeys(accountId: string): Promise<MemberKeys[]> {
    const jsons = await callPort(() => this.#ports.store.list({ type: "member-keys", teamId: this.teamId, accountId }));
    return jsons.map((json) => parseMemberKeys(json, { teamId: this.teamId, accountId })).sort((a, b) => a.memberKeysVersion - b.memberKeysVersion);
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

  #kept(options: RotationOptions, accountId: string) {
    return accountId === this.accountId || options.keep.includes(accountId);
  }

  /** One set of keys per account: approved newest keys, or the keys it holds (§6.6 step 2). */
  async #recipients(holders: readonly Holder[], options: RotationOptions): Promise<Recipient[]> {
    const { suite } = this.#ports;
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
      if (!keys || !suite.equal(keysHash(suite, keys), holder.keysHash)) throw this.#markUnverified(trustFailure("key_mismatch"));
      recipients.push(recipientFromKeys(suite, keys));
    }
    return recipients;
  }

  async #rotate(options: RotationOptions, newOwners: readonly string[] | undefined) {
    const signer = this.#ownerSigner();
    const current = this.#current!;
    const chain = this.#requireChain();
    const kept = (await this.#currentHolders()).filter((h) => this.#kept(options, h.accountId));
    const recipients = await this.#recipients(kept, options);

    const nextKey = this.#ports.suite.randomBytes(this.#ports.suite.sizes.key);
    const currentKey = await this.#teamKey(current.version);
    const owners = newOwners ?? current.owners.map((o) => o.accountId);
    try {
      const version = versionOp(this.#ports, current, chain.hashes.get(current.version)!, currentKey, nextKey, owners, recipients, signer);
      // One record, roster included: a rotation is never half done (§6.6 step 5, D-34).
      await commitTeam(this.#ports.store, [version]);
    } finally {
      this.#ports.suite.wipe(nextKey);
    }
    await this.#load();
    return { version: current.version + 1, granted: recipients.map((r) => r.accountId) };
  }
}
