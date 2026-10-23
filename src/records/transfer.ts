// Moving one team's member keys between contexts (§3.8, D-29). Never stored.
import { open, seal } from "../blocks/seal.js";
import { fromBase64url, toBase64url } from "../encoding/base64url.js";
import { Reader, bytes, list, string, u32, type Field } from "../encoding/canonical.js";
import { malformed, unsupported } from "../errors.js";
import { concat } from "../internal/bytes.js";
import type { KeyPair, Suite } from "../suites/suite.js";
import { encodeFloor, readFloor, type MemberKeyBundle } from "./member-keys-wrap.js";

const PREFIX = "1";
const KEY = 32;
const MAX_BUNDLES = 64;

export interface TransferContext {
  readonly accountId: string;
  readonly teamId: string;
}

export interface TransferBundle extends MemberKeyBundle {
  readonly memberKeysVersion: number;
}

function body(value: string): Uint8Array {
  if (typeof value !== "string" || value.length === 0) throw malformed();
  if (value[0] !== PREFIX) throw unsupported();
  return fromBase64url(value.slice(1));
}

const context = (c: TransferContext): Field[] => [string(c.accountId), string(c.teamId)];

/** The receiver's public key, as a link value (§3.5). */
export function encodeRequest(publicKey: Uint8Array): string {
  return PREFIX + toBase64url(publicKey);
}

/** Throws `UNSUPPORTED_VERSION` for another prefix, `MALFORMED_RECORD` for a bad or low-order key. */
export function decodeRequest(suite: Suite, request: string): Uint8Array {
  const publicKey = body(request);
  if (publicKey.length !== KEY || suite.isLowOrder(publicKey)) throw malformed();
  return publicKey;
}

/** Bundles newest first, 1–64 (§3.8 step 2). */
export function sealTransfer(
  suite: Suite,
  receiverPublicKey: Uint8Array,
  ctx: TransferContext,
  bundles: readonly TransferBundle[],
): string {
  checkBundles(bundles);
  const payload = list(bundles, (b) =>
    concat(u32(b.memberKeysVersion), bytes(b.signingSeed), bytes(b.encryptionSecretKey), bytes(b.teamStateKey), encodeFloor(b.floor)),
  );
  try {
    return PREFIX + toBase64url(seal(suite, receiverPublicKey, "team-keys-transfer", context(ctx), payload));
  } finally {
    suite.wipe(payload);
  }
}

/**
 * §3.8 step 3, up to the published-keys check, which the caller does. Throws
 * `UNSUPPORTED_VERSION`, `DECRYPTION_FAILED` (wrong receiver or context), `MALFORMED_RECORD`.
 */
export function openTransfer(suite: Suite, receiver: KeyPair, ctx: TransferContext, transfer: string): TransferBundle[] {
  const sealed = body(transfer);
  const payload = open(suite, receiver, "team-keys-transfer", context(ctx), sealed);
  try {
    const reader = new Reader(payload);
    const bundles = reader.list(
      (r) => {
        const entry = { memberKeysVersion: r.u32(), signingSeed: r.bytes(), encryptionSecretKey: r.bytes(), teamStateKey: r.bytes() };
        // The bundle's anchor floor (§3.8 step 2, D-48).
        const floor = readFloor(r);
        return floor ? { ...entry, floor } : entry;
      },
      MAX_BUNDLES,
    );
    reader.end();
    checkBundles(bundles);
    return bundles;
  } finally {
    suite.wipe(payload);
  }
}

function checkBundles(bundles: readonly TransferBundle[]) {
  if (bundles.length < 1 || bundles.length > MAX_BUNDLES) throw malformed();
  bundles.forEach((b, i) => {
    const sizes = [b.signingSeed, b.encryptionSecretKey, b.teamStateKey].every((k) => k.length === KEY);
    const ordered = i === 0 || b.memberKeysVersion < bundles[i - 1]!.memberKeysVersion;
    if (!sizes || !ordered || b.memberKeysVersion < 1) throw malformed();
  });
}
