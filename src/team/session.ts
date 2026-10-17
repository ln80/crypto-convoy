// The team session (§6, §9): one team's keys, never the account key (D-03, SP-02).
import { encodeAnchor, type Anchor } from "../encoding/link.js";
import { ConvoyError, isConvoyError, trustFailure } from "../errors.js";
import { callPort } from "../ports.js";
import type { Grant } from "../records/grant.js";
import { hasValidContinuity, parseMemberKeys, type MemberKeys } from "../records/member-keys.js";
import { openPreviousKey, parseTeamKeyVersion, type TeamKeyVersion } from "../records/team-key-version.js";
import type { OpenedPart, PartInput } from "../content/context.js";
import { fetchInbox, readSubmission, storeInbox, type OpenedSubmission } from "../content/inbox.js";
import { fetchItem, readParts, storeItem, streamPart, type PartStream } from "../content/items.js";
import { encodeLinkKey } from "../encoding/link.js";
import { openItemKey } from "../records/item.js";
import { advanceAnchor, collectAnchors, readServerState } from "./anchors.js";
import { isOwner, verifyChain, type OwnerChange, type VerifiedChain } from "./chain.js";
import { commitTeam, type MemberBundle, type TeamPorts } from "./context.js";
import { checkOwnerRule, listGrants, openOwnGrant, type OwnGrant } from "./grants.js";
import { grantOp, recipientFromGrant, recipientFromKeys, versionOp, type Recipient, type Signer } from "./rotation.js";

/** What this account can do in the team (§9). */
export type AccessState = "not-joined" | "pending" | "ready" | "unverified";

/** A member admitted at the current version, and who admitted them (SP-15). */
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

export interface RotationOptions {
  /** Accounts that receive the new version: an allowlist (§6.6). The caller is always kept. */
  readonly keep: readonly string[];
  /** Accounts whose newest published keys are approved by this rotation (§6.8). */
  readonly approveRekeys?: readonly string[];
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
  #own: OwnGrant | undefined;
  #keys = new Map<number, Uint8Array>();
  #ownerChanges: OwnerChange[] = [];

  private constructor(ports: TeamPorts, accountId: string, teamId: string, bundles: readonly MemberBundle[], invite?: Anchor) {
    this.#ports = ports;
    this.accountId = accountId;
    this.teamId = teamId;
    this.#bundles = bundles;
    this.#invite = invite;
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

  /** Grants of the current version, each with its signer (§6.5, SP-15). Throws `TRUST_FAILURE`. */
  async members(): Promise<Member[]> {
    const grants = await this.#currentGrants();
    return grants.map((g) => ({ accountId: g.accountId, memberKeysVersion: g.memberKeysVersion, grantedBy: g.signer.accountId }));
  }

  /** Members whose current grant was signed by one of `accountIds`: review them before removing those owners (§6.7 step 3). */
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
    const previous = keys.find((k) => k.memberKeysVersion === newest.memberKeysVersion - 1);
    const continuity = newest.memberKeysVersion === 1 ? "new" : previous && hasValidContinuity(newest, previous) ? "routine" : "unproven";
    const granted = (await this.#currentGrants()).some(
      (g) => g.accountId === accountId && g.memberKeysVersion === newest.memberKeysVersion,
    );
    return { accountId, memberKeysVersion: newest.memberKeysVersion, continuity, granted };
  }

  /**
   * Grants the current version to the keys the owner confirmed (§6.5). The caller must be an
   * owner. Throws `NOT_GRANTED`, `TRUST_FAILURE` (`not_an_owner`), `STALE_VERSION`.
   */
  async grant(accountId: string, memberKeysVersion: number): Promise<void> {
    const signer = this.#ownerSigner();
    const keys = (await this.#publishedKeys(accountId)).find((k) => k.memberKeysVersion === memberKeysVersion);
    if (!keys) throw new ConvoyError("NOT_GRANTED");
    const teamKey = await this.teamKey(this.currentVersion);
    await commitTeam(this.#ports.store, [grantOp(this.#ports, this.teamId, this.currentVersion, teamKey, recipientFromKeys(keys), signer)]);
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
   * Resumes an interrupted rotation (§6.6 step 7): grants the current version to kept accounts
   * that held the previous one and still miss it. Creates no version.
   */
  async completeRotation(options: RotationOptions): Promise<{ granted: string[] }> {
    const signer = this.#ownerSigner();
    const version = this.currentVersion;
    if (version < 2) return { granted: [] };
    const have = new Set((await this.#currentGrants()).map((g) => g.accountId));
    const previous = await this.#grantsOf(version - 1);
    const missing = previous.filter((g) => this.#kept(options, g.accountId) && !have.has(g.accountId));
    const recipients = await this.#recipients(missing, options);
    const teamKey = await this.teamKey(version);
    const ops = recipients.map((r) => grantOp(this.#ports, this.teamId, version, teamKey, r, signer));
    if (ops.length > 0) await commitTeam(this.#ports.store, ops);
    return { granted: recipients.map((r) => r.accountId) };
  }

  /**
   * Encrypts and stores an item at the current version (§7.1). Parts are plaintext plus an
   * optional opaque `meta` (D-16). Throws `NOT_GRANTED`, `STALE_VERSION` (id used or version changed).
   */
  async createItem(itemId: string, parts: readonly PartInput[]): Promise<void> {
    const version = this.writeVersion();
    await storeItem(this.#ports, { teamId: this.teamId, itemId, teamKeyVersion: version, createdBy: this.accountId }, await this.teamKey(version), parts);
  }

  /**
   * Opens every part of an item, buffered (§7.2): all or nothing. Refuses parts above
   * `maxBufferedSize` before downloading (`MALFORMED_RECORD`). Throws `NOT_GRANTED`, `DECRYPTION_FAILED`.
   */
  async openItem(itemId: string): Promise<OpenedPart[]> {
    const record = await fetchItem(this.#ports, this.teamId, itemId);
    return readParts(this.#ports, record, await this.#itemKey(record));
  }

  /** Opt-in streaming read of one part (§3.4): discard what you received if it ends with an error. */
  async openItemStream(itemId: string, index: number): Promise<PartStream> {
    const record = await fetchItem(this.#ports, this.teamId, itemId);
    return streamPart(this.#ports, record, await this.#itemKey(record), index);
  }

  /** The item key for a share link's fragment (§7.3). Whoever holds the link can read the item (TH-23). */
  async shareLinkKey(itemId: string): Promise<string> {
    const key = await this.#itemKey(await fetchItem(this.#ports, this.teamId, itemId));
    try {
      return encodeLinkKey(key);
    } finally {
      this.#ports.suite.wipe(key);
    }
  }

  /** Creates an inbox at the current version; the link key goes in the inbox link's fragment (§7.4). */
  async createInbox(inboxId: string): Promise<{ linkKey: string }> {
    const version = this.writeVersion();
    return storeInbox(this.#ports, { teamId: this.teamId, inboxId, teamKeyVersion: version, createdBy: this.accountId }, await this.teamKey(version));
  }

  /**
   * A new key pair under the current version, with a new link (§7.4, D-20). Ends a removed
   * member's access to new submissions once the integration retires `inboxId`'s link.
   */
  async replaceInbox(inboxId: string, newInboxId: string): Promise<{ linkKey: string }> {
    await fetchInbox(this.#ports, this.teamId, inboxId);
    return this.createInbox(newInboxId);
  }

  /** Opens a submission, buffered (§7.6). Throws `NOT_GRANTED`, `DECRYPTION_FAILED`, `TRUST_FAILURE` (`key_mismatch`). */
  async openSubmission(inboxId: string, submissionId: string): Promise<OpenedSubmission> {
    const inbox = await fetchInbox(this.#ports, this.teamId, inboxId);
    return readSubmission(this.#ports, inbox, await this.teamKey(inbox.teamKeyVersion), submissionId);
  }

  async #itemKey(record: Parameters<typeof openItemKey>[0]): Promise<Uint8Array> {
    return openItemKey(record, await this.teamKey(record.teamKeyVersion));
  }

  /**
   * @internal The key of `version`, opened through the chain from the granted version (§6.2).
   * Throws `NOT_GRANTED` above the granted version.
   */
  async teamKey(version: number): Promise<Uint8Array> {
    this.#requireUsable();
    const own = this.#own;
    if (!own || version > own.grant.teamKeyVersion || version < 1) throw new ConvoyError("NOT_GRANTED");
    for (let k = own.grant.teamKeyVersion; k > version; k--) {
      if (!this.#keys.has(k - 1)) this.#keys.set(k - 1, openPreviousKey(this.#record(k), this.#keys.get(k)!));
    }
    return this.#keys.get(version)!;
  }

  /** @internal Writes need the current version (§7.1). Throws `NOT_GRANTED`, `STALE_VERSION`. */
  writeVersion(): number {
    this.#requireUsable();
    if (this.#state !== "ready") throw new ConvoyError("NOT_GRANTED");
    return this.currentVersion;
  }

  /** @internal */
  get ports(): TeamPorts {
    return this.#ports;
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
    const { store } = this.#ports;
    const server = await readServerState(this.#ports, this.accountId, this.teamId, this.#bundles);
    const anchors = await collectAnchors(this.#ports, this.accountId, this.teamId, server, this.#invite);
    const records = (await callPort(() => store.list({ type: "team-key-version", teamId: this.teamId, fromVersion: 1 }))).map(
      (json) => parseTeamKeyVersion(json, { teamId: this.teamId }),
    );
    const memberKeys = (await callPort(() => store.list({ type: "member-keys", teamId: this.teamId }))).map((json) =>
      parseMemberKeys(json, { teamId: this.teamId, accountId: (json as { accountId: string }).accountId }),
    );
    const chain = verifyChain({ records, anchors, memberKeys });
    const own = await openOwnGrant(this.#ports, this.teamId, this.accountId, chain, this.#bundles);

    this.#chain = chain;
    this.#ownerChanges = [...chain.ownerChanges];
    this.close();
    this.#own = own ?? undefined;
    if (own) this.#keys.set(own.grant.teamKeyVersion, own.teamKey);
    this.#state = own && own.grant.teamKeyVersion === this.currentVersion ? "ready" : "pending";
    await advanceAnchor(this.#ports, this.accountId, this.teamId, chain, this.#bundles[0]!, server);
  }

  #markUnverified(error: ConvoyError) {
    // Sticky for the session: tampering or a bug, never retried automatically (§9).
    this.#state = "unverified";
    this.#failure = error;
    this.close();
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
    this.writeVersion();
    const current = this.#current!;
    for (const bundle of this.#bundles) {
      const ref = { accountId: this.accountId, signingPublicKey: bundle.pairs.signing.publicKey };
      if (isOwner(current, ref)) return { ref, secretKey: bundle.pairs.signing.secretKey };
    }
    throw trustFailure("not_an_owner");
  }

  async #guard<T>(run: () => Promise<T>): Promise<T> {
    try {
      return await run();
    } catch (error) {
      if (isConvoyError(error, "TRUST_FAILURE")) this.#markUnverified(error);
      throw error;
    }
  }

  async #grantsOf(version: number): Promise<Grant[]> {
    return this.#guard(async () => {
      const chain = this.#requireChain();
      const grants = await listGrants(this.#ports, this.teamId, { teamKeyVersion: version });
      for (const grant of grants) checkOwnerRule(grant, chain);
      return grants;
    });
  }

  #currentGrants(): Promise<Grant[]> {
    return this.#grantsOf(this.currentVersion);
  }

  async #publishedKeys(accountId: string): Promise<MemberKeys[]> {
    const jsons = await callPort(() => this.#ports.store.list({ type: "member-keys", teamId: this.teamId, accountId }));
    return jsons.map((json) => parseMemberKeys(json, { teamId: this.teamId, accountId })).sort((a, b) => a.memberKeysVersion - b.memberKeysVersion);
  }

  #kept(options: RotationOptions, accountId: string) {
    return accountId === this.accountId || options.keep.includes(accountId);
  }

  /** One set of keys per account: approved newest keys, or the granted ones (§6.6 step 2). */
  async #recipients(grants: readonly Grant[], options: RotationOptions): Promise<Recipient[]> {
    const newestGrant = new Map<string, Grant>();
    for (const g of grants) {
      const seen = newestGrant.get(g.accountId);
      if (!seen || g.memberKeysVersion > seen.memberKeysVersion) newestGrant.set(g.accountId, g);
    }
    const recipients: Recipient[] = [];
    for (const [accountId, grant] of newestGrant) {
      if (options.approveRekeys?.includes(accountId)) {
        const newest = (await this.#publishedKeys(accountId)).at(-1)!;
        recipients.push(recipientFromKeys(newest));
      } else {
        recipients.push(recipientFromGrant(grant));
      }
    }
    return recipients;
  }

  async #rotate(options: RotationOptions, newOwners: readonly string[] | undefined) {
    const signer = this.#ownerSigner();
    const current = this.#current!;
    const chain = this.#requireChain();
    const kept = (await this.#currentGrants()).filter((g) => this.#kept(options, g.accountId));
    const recipients = await this.#recipients(kept, options);
    const self = recipients.find((r) => r.accountId === this.accountId)!;

    const nextKey = this.#ports.suite.randomBytes(this.#ports.suite.sizes.key);
    const currentKey = await this.teamKey(current.version);
    const owners = newOwners ?? current.owners.map((o) => o.accountId);
    const version = versionOp(this.#ports, current, chain.hashes.get(current.version)!, currentKey, nextKey, owners, recipients, signer);
    // The version and its signer's grant in one batch: this makes it current (§6.6 step 5).
    await commitTeam(this.#ports.store, [version, grantOp(this.#ports, this.teamId, current.version + 1, nextKey, self, signer)]);

    const others = recipients.filter((r) => r !== self);
    if (others.length > 0) {
      await commitTeam(this.#ports.store, others.map((r) => grantOp(this.#ports, this.teamId, current.version + 1, nextKey, r, signer)));
    }
    this.#ports.suite.wipe(nextKey);
    await this.#load();
    return { version: current.version + 1, granted: recipients.map((r) => r.accountId) };
  }
}
