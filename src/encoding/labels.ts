// Labels of protocol §1. Released names never change (§10); a new purpose is a new name.
import { enc, string, type Field } from "./canonical.js";

export const LABEL_PREFIX = "crypto-convoy/v1/";

export const LABELS = [
  "pin-key",
  "pin-oprf",
  "recovery-key",
  "recovery-signing-key",
  "recovery-public-key",
  "account-key-wrap",
  "member-keys",
  "member-keys-recovery",
  "member-keys-hash",
  "member-keys-wrap",
  "team-key-version",
  "team-key-link",
  "roster-seal",
  "item-key",
  "item-manifest",
  "item-part",
  "inbox-key",
  "submission",
  "submission-part",
  "part-ref",
  "team-keys-transfer",
  "local-device-key",
  "local-account-version",
  "local-anchor",
  "local-vault-anchor",
] as const;

export type Label = (typeof LABELS)[number];

/** `string label(name)`: the first field of every canonical payload. */
export function labelField(name: Label): Field {
  return string(LABEL_PREFIX + name);
}

/** `enc(string label(name), fields…)`. */
export function labelled(name: Label, ...fields: readonly Field[]): Uint8Array {
  return enc(labelField(name), ...fields);
}
