/**
 * crypto-convoy: end-to-end encrypted team storage. High-level operations only (D-15):
 * keys stay inside the library; applications pass plaintext and get plaintext back.
 */

/** Package version. */
export const version = "0.0.0";

export { createVault, type Vault, type VaultOptions } from "./account/vault.js";
export type {
  AccessState,
  Member,
  MemberRequest,
  RotationOptions,
  TeamSession,
} from "./team/session.js";
export type { OwnerChange } from "./team/chain.js";
export { createLinkClient, type LinkClient, type LinkClientOptions } from "./content/link-client.js";
export type { OpenedPart, PartInput } from "./content/context.js";
export type { PartStream } from "./content/items.js";
export type { OpenedSubmission } from "./content/inbox.js";

export {
  ConvoyError,
  RateLimitedError,
  StoreConflictError,
  isConvoyError,
  type ErrorCode,
  type TrustReason,
} from "./errors.js";

export type {
  Argon2Cost,
  Clock,
  LocalAnchor,
  LocalDevice,
  LocalKeyStore,
  OprfPurpose,
  OprfService,
  PartKey,
  RecordKey,
  RecordQuery,
  RecordStore,
  Settings,
  TeamStateKey,
  WireRecord,
  WriteOp,
} from "./ports.js";
