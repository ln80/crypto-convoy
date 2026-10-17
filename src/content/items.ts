// Item drafts and opened items (§7.1–§7.3), independent of where content is stored.
import { encryptItemPart, encryptItemPartStream, openManifest, openPart, openPartStream, type Item } from "../records/item.js";
import type { ManifestEntry } from "../records/manifest.js";
import type { ContentPorts } from "./context.js";
import { Draft } from "./draft.js";
import { OpenedItem } from "./opened.js";

/** Seals with the item's id. */
export type ItemDraft = Draft<[itemId: string], void>;

export function newItemDraft(
  ports: ContentPorts,
  seal: (itemKey: Uint8Array, manifest: readonly ManifestEntry[], itemId: string) => Promise<void>,
): ItemDraft {
  const { suite } = ports;
  return new Draft(
    suite,
    (key, index, content) => encryptItemPart(suite, key, index, content),
    (key, index, source, done) => encryptItemPartStream(suite, key, index, source, done),
    seal,
  );
}

/** Takes ownership of `itemKey`: closing the opened item wipes it. */
export function openedItem(ports: ContentPorts, record: Item, itemKey: Uint8Array): OpenedItem {
  const manifest = openManifest(record, itemKey);
  return new OpenedItem(
    ports.suite,
    manifest,
    ports.settings.maxBufferedSize,
    (entry, ciphertext) => openPart(record, itemKey, entry, ciphertext),
    (entry, source) => openPartStream(record, itemKey, entry, source),
    () => ports.suite.wipe(itemKey),
  );
}
