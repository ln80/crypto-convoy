// Items: create, open buffered or streamed (§7.1, §7.2).
import { ConvoyError, decryptionFailed, malformed } from "../errors.js";
import { callPort, commitContent } from "./store.js";
import type { PartKey } from "../ports.js";
import {
  checkPartCount,
  createItem,
  itemToJson,
  openManifest,
  openPart,
  openPartStream,
  parseItem,
  type Item,
} from "../records/item.js";
import type { ManifestEntry } from "../records/manifest.js";
import type { ContentPorts, OpenedPart, PartInput } from "./context.js";

const partKey = (record: Item, index: number): PartKey => ({ type: "item-part", teamId: record.teamId, itemId: record.itemId, index });

/** Encrypts and stores an item: the record and its parts in one batch, so content never exists without its key (§7.1). */
export async function storeItem(
  ports: ContentPorts,
  input: { teamId: string; itemId: string; teamKeyVersion: number; createdBy: string },
  teamKey: Uint8Array,
  parts: readonly PartInput[],
): Promise<void> {
  checkPartCount(parts.length);
  const { record, parts: ciphertexts } = createItem(ports.suite, { ...input, createdAt: ports.clock.now() }, teamKey, parts);
  await commitContent(ports.store, [
    { op: "create", key: { type: "item", teamId: input.teamId, itemId: input.itemId }, record: itemToJson(record) },
    ...ciphertexts.map((bytes, index) => ({ op: "create-part" as const, key: partKey(record, index), bytes })),
  ]);
}

export async function fetchItem(ports: ContentPorts, teamId: string, itemId: string): Promise<Item> {
  const json = await callPort(() => ports.store.get({ type: "item", teamId, itemId }));
  if (json === null || json === undefined) throw new ConvoyError("STORE_ERROR");
  return parseItem(json, { teamId, itemId });
}

/** Buffered read (§7.2 step 3): every part complete and authenticated, or an error and nothing (SP-18). */
export async function readParts(ports: ContentPorts, record: Item, itemKey: Uint8Array): Promise<OpenedPart[]> {
  const manifest = openManifest(record, itemKey);
  // Refused before any download (§3.4, TH-25).
  if (manifest.some((e) => e.ciphertextSize > ports.settings.maxBufferedSize)) throw malformed();
  const opened: OpenedPart[] = [];
  try {
    for (const entry of manifest) {
      const ciphertext = await callPort(() => ports.store.getPart(partKey(record, entry.index)));
      if (!ciphertext) throw decryptionFailed();
      opened.push({ content: openPart(record, itemKey, entry, ciphertext), meta: entry.meta });
    }
    return opened;
  } catch (error) {
    for (const part of opened) ports.suite.wipe(part.content);
    throw error;
  }
}

export interface PartStream {
  readonly meta: Uint8Array;
  readonly size: number;
  /** Authenticated chunks; ends with `DECRYPTION_FAILED` if incomplete: discard what was received. */
  readonly chunks: AsyncIterable<Uint8Array>;
}

/** Opt-in streaming read of one part (§3.4). */
export async function streamPart(ports: ContentPorts, record: Item, itemKey: Uint8Array, index: number): Promise<PartStream> {
  const manifest = openManifest(record, itemKey);
  const entry = manifest[index];
  if (!entry) throw malformed();
  return { meta: entry.meta, size: entry.ciphertextSize, chunks: openPartStream(record, itemKey, entry, await partSource(ports, partKey(record, index))) };
}

export async function partSource(ports: ContentPorts, key: PartKey): Promise<AsyncIterable<Uint8Array>> {
  const { store } = ports;
  const stream = store.getPartStream ? await callPort(() => store.getPartStream!(key)) : null;
  if (stream) return stream;
  const bytes = await callPort(() => store.getPart(key));
  if (!bytes) throw decryptionFailed();
  return (async function* () {
    yield bytes;
  })();
}

export type { ManifestEntry };
