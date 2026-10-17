// Opening an item from a share link (§7.3): the item key from the fragment, nothing else.
import { decodeLinkKey } from "../encoding/link.js";
import type { ContentPorts, OpenedPart } from "./context.js";
import { fetchItem, readParts, streamPart, type PartStream } from "./items.js";

/**
 * Opens a shared item. The recipient gets integrity of the content and manifest only:
 * `createdBy` and the team key version can't be checked without the team key (§7.3).
 */
export async function openSharedItem(ports: ContentPorts, linkKey: string, teamId: string, itemId: string): Promise<OpenedPart[]> {
  const itemKey = decodeLinkKey(linkKey);
  try {
    return await readParts(ports, await fetchItem(ports, teamId, itemId), itemKey);
  } finally {
    ports.suite.wipe(itemKey);
  }
}

export async function openSharedItemStream(ports: ContentPorts, linkKey: string, teamId: string, itemId: string, index: number): Promise<PartStream> {
  return streamPart(ports, await fetchItem(ports, teamId, itemId), decodeLinkKey(linkKey), index);
}
