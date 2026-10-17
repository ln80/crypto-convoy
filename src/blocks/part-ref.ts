// Part references (§3.9, D-28): keyed per item or submission, safe to send to a server.
import { toBase64url } from "../encoding/base64url.js";
import { labelled } from "../encoding/labels.js";
import type { Suite } from "../suites/suite.js";

/** One job per key: the content key never hashes content itself. */
export function partRefKey(suite: Suite, contentKey: Uint8Array): Uint8Array {
  return suite.keyedHash(contentKey, labelled("part-ref"));
}

export function partRef(suite: Suite, refKey: Uint8Array, content: Uint8Array): string {
  return toBase64url(suite.keyedHash(refKey, content));
}

/** The same reference, computed over a stream of chunks. */
export async function partRefStream(suite: Suite, refKey: Uint8Array, chunks: AsyncIterable<Uint8Array>): Promise<string> {
  const hasher = suite.hasher(refKey);
  for await (const chunk of chunks) hasher.update(chunk);
  return toBase64url(hasher.digest());
}
