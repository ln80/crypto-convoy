// The team session (§6, §9): one team's keys, never the account key (D-03, SP-02). Owner
// operations live on `TeamOwner` (§6.5–§6.9), reached through `owner()`.
import { encodeAnchor, type Anchor } from "../encoding/link.js";
import { ConvoyError, isConvoyError } from "../errors.js";
import { callPort } from "../ports.js";
import { openPreviousKey, type TeamKeyVersion } from "../records/team-key-version.js";
import { fetchInbox, openSubmissionRecord, storeInbox } from "../content/inbox.js";
import { newItemDraft, openedItem, type ItemDraft } from "../content/items.js";
import type { OpenedItem, OpenedSubmission } from "../content/opened.js";
import { encodeLinkKey } from "../encoding/link.js";
import { itemToJson, openItemKey, parseItem, sealItem, type Item } from "../records/item.js";
import { advanceAnchor } from "./anchors.js";
import { chainFrom, loadChain } from "./load.js";
import { isOwner, type MemberChange, type OwnerChange, type VerifiedChain } from "./chain.js";
import { commitTeam, type MemberBundle, type TeamPorts } from "./context.js";
import { holdersOf, openOwnAccess, type Holder, type OwnAccess } from "./access.js";
import { TeamOwner } from "./owner.js";
import type { Signer } from "./rotation.js";

/** What this account can do in the team (§9). */
export type AccessState = "not-joined" | "pending" | "ready" | "unverified";

/** A member holding the current version, and who gave it to them (SP-15). */
export interface Member {
  readonly accountId: string;
  readonly memberKeysVersion: number;
  readonly grantedBy: string;
}

/** Library-only access to a session's keys, chain and ports, for `TeamOwner` and tests. Never exported from the package entry (D-15). */
export interface SessionInternals {
  readonly ports: TeamPorts;
  readonly teamId: string;
  readonly accountId: string;
  teamKey(version: number): Promise<Uint8Array>;
  writeVersion(): number;
  current(): TeamKeyVersion;
  currentHash(): Uint8Array;
  /** The verified chain reaching down to `version`. Throws `TRUST_FAILURE`. */
  chainFrom(version: number): Promise<VerifiedChain>;
  holdersOf(version: number): Promise<Holder[]>;
  /** The caller's owner keys for the current version. Throws `NOT_GRANTED`, `NOT_AN_OWNER`. */
  ownerSigner(): Signer;
  /** Runs `run`; a `TRUST_FAILURE` makes the session `unverified` (§9). */
  guard<T>(run: () => Promise<T>): Promise<T>;
  markUnverified(error: ConvoyError): ConvoyError;
  /** Reloads and verifies the team after a write (§6.1). */
  reload(): Promise<void>;
}

const INTERNALS = new WeakMap<TeamSession, SessionInternals>();

export function sessionInternals(session: TeamSession): SessionInternals {
  return INTERNALS.get(session)!;
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
  #memberChanges: MemberChange[] = [];

  private constructor(ports: TeamPorts, accountId: string, teamId: string, bundles: readonly MemberBundle[], invite?: Anchor) {
    this.#ports = ports;
    this.accountId = accountId;
    this.teamId = teamId;
    this.#bundles = bundles;
    this.#invite = invite;
    INTERNALS.set(this, {
      ports,
      teamId,
      accountId,
      teamKey: (v) => this.#teamKey(v),
      writeVersion: () => this.#writeVersion(),
      current: () => this.#requireChain().records.at(-1)!,
      currentHash: () => this.#requireChain().hashes.get(this.currentVersion)!,
      chainFrom: (v) => this.#chainFrom(v),
      holdersOf: (v) => this.#holdersOf(v),
      ownerSigner: () => this.#ownerSigner(),
      guard: (run) => this.#guard(run),
      markUnverified: (error) => this.#markUnverified(error),
      reload: () => this.#load(),
    });
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

  /** Roster changes since this account's last verified state: who was added, removed or re-keyed, and by whom (SP-15, D-44). */
  get memberChanges(): readonly MemberChange[] {
    return this.#memberChanges;
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

  /** Holders of the current version (its roster), each with who signed it (§6.5, SP-15). Throws `TRUST_FAILURE`. */
  async members(): Promise<Member[]> {
    const holders = await this.#currentHolders();
    return holders.map((h) => ({ accountId: h.accountId, memberKeysVersion: h.memberKeysVersion, grantedBy: h.signer.accountId }));
  }

  /**
   * Owner operations for this team (§6.5–§6.9): overview, `reconcile`, approvals, removals,
   * owner changes, invites. Throws `NOT_GRANTED` (no current access), `NOT_AN_OWNER`.
   */
  owner(): TeamOwner {
    this.#ownerSigner();
    return new TeamOwner(INTERNALS.get(this)!);
  }

  /**
   * Starts an item (§7.1, D-27): add parts, store their ciphertext yourself, then `seal(itemId)`
   * stores the `item` record at the version current then, retrying once if an owner rotated
   * meanwhile. Throws `NOT_GRANTED`; `seal` throws `NOT_GRANTED` or `STALE_VERSION` (id used).
   */
  beginItem(): ItemDraft {
    this.#writeVersion();
    return newItemDraft(this.#ports, (itemKey, manifest, itemId) =>
      this.#atCurrentVersion(async (version) => {
        const record = sealItem(
          this.#ports.suite,
          { teamId: this.teamId, itemId, teamKeyVersion: version, createdBy: this.accountId, createdAt: this.#ports.clock.now() },
          await this.#teamKey(version),
          itemKey,
          manifest,
        );
        await commitTeam(this.#ports.store, [{ op: "create", key: { type: "item", teamId: this.teamId, itemId }, record: itemToJson(record) }]);
      }),
    );
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

  /** Creates an inbox at the current version, retrying once if it moved; the link key goes in the inbox link's fragment (§7.4). */
  async createInbox(inboxId: string): Promise<{ linkKey: string }> {
    return this.#atCurrentVersion(async (version) =>
      storeInbox(this.#ports, this.#ports.store, { teamId: this.teamId, inboxId, teamKeyVersion: version, createdBy: this.accountId }, await this.#teamKey(version)),
    );
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

  async #fetchItem(itemId: string): Promise<Item> {
    const json = await callPort(() => this.#ports.store.get({ type: "item", teamId: this.teamId, itemId }));
    if (json === null || json === undefined) throw new ConvoyError("STORE_ERROR");
    return parseItem(json, { teamId: this.teamId, itemId });
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

  /**
   * Runs a write at the current version. If the server refuses it and the version moved (an owner
   * rotated, D-37), reloads and writes once more at the new one; otherwise the refusal stands
   * (§7.1, §7.4). Throws `NOT_GRANTED`, `STALE_VERSION`.
   */
  async #atCurrentVersion<T>(write: (version: number) => Promise<T>): Promise<T> {
    const version = this.#writeVersion();
    try {
      return await write(version);
    } catch (error) {
      if (!isConvoyError(error, "STALE_VERSION")) throw error;
      await this.#load();
      if (this.currentVersion === version) throw error;
      return write(this.#writeVersion());
    }
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
    const own = await openOwnAccess(this.#ports, this.accountId, chain, (v) => chainFrom(this.#ports, this.teamId, chain, v), this.#bundles);

    this.#chain = own?.chain ?? chain;
    this.#ownerChanges = [...chain.ownerChanges];
    this.#memberChanges = [...chain.memberChanges];
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

  /** The caller's keys listed among the current owners; their own access must be current. */
  #ownerSigner(): Signer {
    this.#writeVersion();
    const current = this.#current!;
    for (const bundle of this.#bundles) {
      const ref = { accountId: this.accountId, signingPublicKey: bundle.pairs.signing.publicKey };
      if (isOwner(current, ref)) return { ref, secretKey: bundle.pairs.signing.secretKey };
    }
    throw new ConvoyError("NOT_AN_OWNER");
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

  /** Who holds `version`: its roster (D-37). Throws `TRUST_FAILURE`. */
  async #holdersOf(version: number): Promise<Holder[]> {
    return this.#guard(async () => {
      await this.#chainFrom(version);
      return holdersOf(this.#record(version));
    });
  }

  #currentHolders(): Promise<Holder[]> {
    return this.#holdersOf(this.currentVersion);
  }
}
