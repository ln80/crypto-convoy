// What a client outside the team can do (§7.3, §7.5): no account and no store.
import { decodeLinkKey } from "../encoding/link.js";
import { resolveSettings, systemClock, type Clock, type Settings } from "../ports.js";
import { parseItem } from "../records/item.js";
import { CURRENT_SUITE, ready } from "../suites/registry.js";
import { newSubmissionDraft, type SubmissionDraft } from "./inbox.js";
import { openedItem } from "./items.js";
import type { OpenedItem } from "./opened.js";

export interface LinkClientOptions {
  readonly clock?: Clock;
  /** Only `maxBufferedSize` matters here. */
  readonly settings?: Settings;
}

export interface LinkClient {
  /**
   * Opens a shared item from its link key and its `item` record, which the integration serves by
   * the route it chooses (§7.3). Parts are then opened on demand. Throws `MALFORMED_RECORD`,
   * `UNSUPPORTED_VERSION`, `TRUST_FAILURE` (`context_mismatch`), `DECRYPTION_FAILED`.
   */
  openSharedItem(linkKey: string, teamId: string, itemId: string, itemRecord: unknown): OpenedItem;
  /** Starts a submission sealed to the inbox key from the link (§7.5, SP-14). */
  beginSubmission(linkKey: string, teamId: string, inboxId: string): SubmissionDraft;
}

/** A client with no account. Loads libsodium. */
export async function createLinkClient(options: LinkClientOptions = {}): Promise<LinkClient> {
  await ready();
  const ports = { suite: CURRENT_SUITE, clock: options.clock ?? systemClock, settings: resolveSettings(options.settings) };
  return {
    openSharedItem: (linkKey, teamId, itemId, itemRecord) =>
      openedItem(ports, parseItem(itemRecord, { teamId, itemId }), decodeLinkKey(linkKey)),
    beginSubmission: (linkKey, teamId, inboxId) => newSubmissionDraft(ports, linkKey, teamId, inboxId),
  };
}
