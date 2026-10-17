// Link values (§3.5): a one-character format version, then base64url.
import { malformed, unsupported } from "../errors.js";
import { fromBase64url, toBase64url } from "./base64url.js";
import { checkId } from "./json.js";
import { enc, Reader, bytes, string, u32 } from "./canonical.js";

const PREFIX = "1";
const KEY_LENGTH = 32;
const HASH_LENGTH = 32;

/** The anchor carried by an invite link (§6.4). */
export interface Anchor {
  readonly version: number;
  readonly hash: Uint8Array;
}

function body(value: string): string {
  if (typeof value !== "string" || value.length === 0) throw malformed();
  if (value[0] !== PREFIX) throw unsupported();
  return value.slice(1);
}

export function encodeLinkKey(key: Uint8Array): string {
  if (key.length !== KEY_LENGTH) throw malformed();
  return PREFIX + toBase64url(key);
}

/** Prefix and length only; an inbox key's low-order check is the caller's (§2). */
export function decodeLinkKey(value: string): Uint8Array {
  return fromBase64url(body(value), KEY_LENGTH);
}

export function encodeAnchor(anchor: Anchor): string {
  if (anchor.version < 1 || anchor.hash.length !== HASH_LENGTH) throw malformed();
  return PREFIX + toBase64url(enc(u32(anchor.version), bytes(anchor.hash)));
}

export function decodeAnchor(value: string): Anchor {
  const reader = new Reader(fromBase64url(body(value)));
  const version = reader.u32();
  const hash = reader.bytes();
  reader.end();
  if (version < 1 || hash.length !== HASH_LENGTH) throw malformed();
  return { version, hash };
}

/** An invite link value: the team's anchor and an invite's join secret (§3.5, §4.11). */
export interface InviteLink {
  readonly anchor: Anchor;
  readonly inviteId: string;
  readonly secret: Uint8Array;
}

export function encodeInvite(invite: InviteLink): string {
  const { anchor, inviteId, secret } = invite;
  if (anchor.version < 1 || anchor.hash.length !== HASH_LENGTH || secret.length !== KEY_LENGTH) throw malformed();
  return PREFIX + toBase64url(enc(u32(anchor.version), bytes(anchor.hash), string(checkId(inviteId)), bytes(secret)));
}

export function decodeInvite(value: string): InviteLink {
  const reader = new Reader(fromBase64url(body(value)));
  const version = reader.u32();
  const hash = reader.bytes();
  const inviteId = reader.string();
  const secret = reader.bytes();
  reader.end();
  if (version < 1 || hash.length !== HASH_LENGTH || secret.length !== KEY_LENGTH) throw malformed();
  return { anchor: { version, hash }, inviteId: checkId(inviteId), secret };
}
