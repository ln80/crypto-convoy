// item (§4.7) and item parts (§4.8).
import { streamDecrypt, streamDecryptChunks, streamEncrypt, streamEncryptChunks, type EncryptedStream } from "../blocks/stream.js";
import { unwrap, wrap, wrappedHash, type Wrapped } from "../blocks/wrap.js";
import { Reader, bytes, string, u32, u64, type Field } from "../encoding/canonical.js";
import { LIMITS, type JsonRecord } from "../encoding/json.js";
import { decryptionFailed } from "../errors.js";
import type { Suite } from "../suites/suite.js";
import { expectContext, readRecord, readWrapped, writeHeader, writeWrapped, type RecordHeader } from "./common.js";
import { encodeManifest, readManifest, type ManifestEntry } from "./manifest.js";

export const ITEM = "item";

interface ItemContext {
  readonly teamId: string;
  readonly itemId: string;
}

export interface Item extends RecordHeader, ItemContext {
  readonly teamKeyVersion: number;
  readonly createdBy: string;
  readonly createdAt: number;
  readonly wrappedManifest: Wrapped;
  readonly wrappedItemKey: Wrapped;
}

/** A part to encrypt, or a part opened. */
export interface Part {
  readonly content: Uint8Array;
  readonly meta?: Uint8Array;
}

const KEY = 32;
const MANIFEST_MAX = 4 + LIMITS.parts * (4 + 8 + 4 + 32 + 4 + LIMITS.meta);

const manifestContext = (c: ItemContext): Field[] => [string(c.teamId), string(c.itemId)];
// A part binds only its index: its item's own key and the manifest tie it to the item (D-26).
const partContext = (index: number): Field[] => [u32(index)];
const itemKeyContext = (suite: Suite, r: Omit<Item, "v" | "suite" | "wrappedItemKey">): Field[] => [
  string(r.teamId),
  string(r.itemId),
  u32(r.teamKeyVersion),
  string(r.createdBy),
  u64(r.createdAt),
  bytes(wrappedHash(suite, r.wrappedManifest)),
];

interface NewItem extends ItemContext {
  readonly teamKeyVersion: number;
  readonly createdBy: string;
  readonly createdAt: number;
}

export function encryptItemPart(suite: Suite, itemKey: Uint8Array, index: number, content: Uint8Array): EncryptedStream {
  return streamEncrypt(suite, itemKey, "item-part", partContext(index), content);
}

export function encryptItemPartStream(
  suite: Suite,
  itemKey: Uint8Array,
  index: number,
  source: AsyncIterable<Uint8Array>,
  onComplete: (result: { size: number; hash: Uint8Array }) => void,
): AsyncGenerator<Uint8Array, void, undefined> {
  return streamEncryptChunks(suite, itemKey, "item-part", partContext(index), source, onComplete);
}

/** Seals a draft (§7.1 step 4): the manifest under the item key, the item key under `teamKey`. */
export function sealItem(
  suite: Suite,
  input: NewItem,
  teamKey: Uint8Array,
  itemKey: Uint8Array,
  manifest: readonly ManifestEntry[],
): Item {
  const wrappedManifest = wrap(suite, itemKey, "item-manifest", manifestContext(input), encodeManifest(manifest));
  const unkeyed = { ...input, wrappedManifest };
  return { v: 1, suite, ...unkeyed, wrappedItemKey: wrap(suite, teamKey, "item-key", itemKeyContext(suite, unkeyed), itemKey) };
}

/** Everything at once, for small items and tests. */
export function createItem(
  suite: Suite,
  input: NewItem,
  teamKey: Uint8Array,
  parts: readonly Part[],
): { record: Item; parts: Uint8Array[] } {
  const itemKey = suite.randomBytes(KEY);
  try {
    const encrypted = parts.map((part, index) => encryptItemPart(suite, itemKey, index, part.content));
    const manifest = encrypted.map((part, index) => ({
      index,
      ciphertextSize: part.ciphertext.length,
      ciphertextHash: part.hash,
      meta: parts[index]!.meta ?? new Uint8Array(0),
    }));
    return { record: sealItem(suite, input, teamKey, itemKey, manifest), parts: encrypted.map((p) => p.ciphertext) };
  } finally {
    suite.wipe(itemKey);
  }
}

export function parseItem(json: unknown, expected: ItemContext): Item {
  const { header, fields } = readRecord(json, ITEM, [
    "teamId",
    "itemId",
    "teamKeyVersion",
    "createdBy",
    "createdAt",
    "wrappedManifest",
    "wrappedItemKey",
  ]);
  const { suite } = header;
  const record: Item = {
    ...header,
    teamId: fields.id("teamId"),
    itemId: fields.id("itemId"),
    teamKeyVersion: fields.u32("teamKeyVersion", 1),
    createdBy: fields.id("createdBy"),
    createdAt: fields.int("createdAt"),
    wrappedManifest: readWrapped(fields, "wrappedManifest", suite, MANIFEST_MAX + suite.sizes.tag),
    wrappedItemKey: readWrapped(fields, "wrappedItemKey", suite, KEY + suite.sizes.tag),
  };
  expectContext({ ...expected }, { ...record });
  return record;
}

/** Member path (§7.2): the item key from the team key. Throws `DECRYPTION_FAILED`. */
export function openItemKey(record: Item, teamKey: Uint8Array): Uint8Array {
  const itemKey = unwrap(record.suite, teamKey, "item-key", itemKeyContext(record.suite, record), record.wrappedItemKey);
  if (itemKey.length !== KEY) throw decryptionFailed();
  return itemKey;
}

/** Member and link-share path (§7.2, §7.3). Throws `DECRYPTION_FAILED` or `MALFORMED_RECORD`. */
export function openManifest(record: Item, itemKey: Uint8Array): ManifestEntry[] {
  const plaintext = unwrap(record.suite, itemKey, "item-manifest", manifestContext(record), record.wrappedManifest);
  const reader = new Reader(plaintext);
  const entries = readManifest(reader);
  reader.end();
  return entries;
}

/** §4.8: size and hash against the manifest, then the stream. Throws `DECRYPTION_FAILED`. */
export function openPart(record: Item, itemKey: Uint8Array, entry: ManifestEntry, ciphertext: Uint8Array): Uint8Array {
  checkPart(record.suite, entry, ciphertext);
  return streamDecrypt(record.suite, itemKey, "item-part", partContext(entry.index), ciphertext);
}

export function openPartStream(
  record: Item,
  itemKey: Uint8Array,
  entry: ManifestEntry,
  source: AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array, void, undefined> {
  return streamDecryptChunks(record.suite, itemKey, "item-part", partContext(entry.index), source, {
    size: entry.ciphertextSize,
    hash: entry.ciphertextHash,
  });
}

export function checkPart(suite: Suite, entry: ManifestEntry, ciphertext: Uint8Array): void {
  if (ciphertext.length !== entry.ciphertextSize) throw decryptionFailed();
  if (!suite.equal(suite.hash(ciphertext), entry.ciphertextHash)) throw decryptionFailed();
}

export function itemToJson(record: Item): JsonRecord {
  return {
    ...writeHeader(ITEM, record.suite),
    teamId: record.teamId,
    itemId: record.itemId,
    teamKeyVersion: record.teamKeyVersion,
    createdBy: record.createdBy,
    createdAt: record.createdAt,
    wrappedManifest: writeWrapped(record.wrappedManifest),
    wrappedItemKey: writeWrapped(record.wrappedItemKey),
  };
}
