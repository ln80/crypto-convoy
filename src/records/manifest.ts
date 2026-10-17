// The list of parts of an item or a submission (D-16): list<u32 index, u64 ciphertextSize, bytes ciphertextHash, bytes meta>.
import { Reader, bytes, list, u32, u64 } from "../encoding/canonical.js";
import { LIMITS } from "../encoding/json.js";
import { concat } from "../internal/bytes.js";
import { malformed } from "../errors.js";

export interface ManifestEntry {
  readonly index: number;
  readonly ciphertextSize: number;
  readonly ciphertextHash: Uint8Array;
  /** Opaque to the library: encrypted and authenticated, never read (D-16). */
  readonly meta: Uint8Array;
}

const HASH = 32;

export function encodeManifest(entries: readonly ManifestEntry[]): Uint8Array {
  checkManifest(entries);
  return list(entries, (e) => concat(u32(e.index), u64(e.ciphertextSize), bytes(e.ciphertextHash), bytes(e.meta)));
}

export function readManifest(reader: Reader): ManifestEntry[] {
  const entries = reader.list(
    (r) => ({ index: r.u32(), ciphertextSize: r.u64(), ciphertextHash: r.bytes(), meta: r.bytes() }),
    LIMITS.parts,
  );
  checkManifest(entries);
  return entries;
}

/** §4.7: indexes 0, 1, … in order, 1–128 parts, `meta` up to 4096 bytes. */
export function checkManifest(entries: readonly ManifestEntry[]): void {
  if (entries.length < 1 || entries.length > LIMITS.parts) throw malformed();
  entries.forEach((e, i) => {
    if (e.index !== i || e.ciphertextHash.length !== HASH || e.meta.length > LIMITS.meta) throw malformed();
  });
}
