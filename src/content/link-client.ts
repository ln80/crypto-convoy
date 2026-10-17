// What a client outside the team can do: open a shared item, submit to an inbox (§7.3, §7.5).
import { resolveSettings, systemClock, type Clock, type RecordStore, type Settings } from "../ports.js";
import { CURRENT_SUITE, ready } from "../suites/registry.js";
import type { OpenedPart, PartInput } from "./context.js";
import { submit } from "./inbox.js";
import type { PartStream } from "./items.js";
import { openSharedItem, openSharedItemStream } from "./link-share.js";

export interface LinkClientOptions {
  readonly store: RecordStore;
  readonly clock?: Clock;
  /** Only `maxBufferedSize` matters here. */
  readonly settings?: Settings;
}

export interface LinkClient {
  /** Opens every part of a shared item, buffered (§7.3). Throws `MALFORMED_RECORD`, `UNSUPPORTED_VERSION`, `DECRYPTION_FAILED`. */
  openSharedItem(linkKey: string, teamId: string, itemId: string): Promise<OpenedPart[]>;
  /** Opt-in streaming read of one part of a shared item (§3.4). */
  openSharedItemStream(linkKey: string, teamId: string, itemId: string, index: number): Promise<PartStream>;
  /**
   * Encrypts and stores a submission, sealed to the inbox key from the link (§7.5, SP-14).
   * Never fetch that key from a server instead (TH-21).
   */
  submitToInbox(linkKey: string, teamId: string, inboxId: string, parts: readonly PartInput[]): Promise<{ submissionId: string }>;
}

/** A client with no account. Loads libsodium. */
export async function createLinkClient(options: LinkClientOptions): Promise<LinkClient> {
  await ready();
  const ports = {
    suite: CURRENT_SUITE,
    store: options.store,
    clock: options.clock ?? systemClock,
    settings: resolveSettings(options.settings),
  };
  return {
    openSharedItem: (linkKey, teamId, itemId) => openSharedItem(ports, linkKey, teamId, itemId),
    openSharedItemStream: (linkKey, teamId, itemId, index) => openSharedItemStream(ports, linkKey, teamId, itemId, index),
    submitToInbox: (linkKey, teamId, inboxId, parts) => submit(ports, linkKey, teamId, inboxId, parts),
  };
}
