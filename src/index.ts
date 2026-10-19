/**
 * crypto-convoy: end-to-end encrypted team storage. High-level operations only (D-15):
 * keys stay inside the library; applications pass plaintext and get plaintext back.
 */

/** Package version. */
export const version = "0.0.0";

export { createVault, type RekeyReport, type Vault, type VaultOptions, type VaultStatus, type VaultWarning } from "./account/vault.js";
export type { AccessState, Member, TeamSession } from "./team/session.js";
export type { ChangeReport, ReconcileOptions, ReconcileReport, RotationOptions, TeamOwner } from "./team/owner.js";
export type {
  AccountOverview,
  AccountStatus,
  HumanReason,
  KeysHandle,
  NeedsHuman,
  OwnerWarning,
  ProofKind,
  TeamOverview,
} from "./team/membership.js";
export type { OwnerChange } from "./team/chain.js";
export { createTeamKeyReceiver, type ReceiverPorts, type TeamKeyReceiver } from "./team/receiver.js";
export { createLinkClient, type LinkClient, type LinkClientOptions } from "./content/link-client.js";
export type { PartInfo, PartOptions, PartSource } from "./content/context.js";
export type { Draft } from "./content/draft.js";
export type { ItemDraft } from "./content/items.js";
export type { SubmissionDraft } from "./content/inbox.js";
export type { OpenedItem, OpenedSubmission } from "./content/opened.js";

export {
  ConvoyError,
  RateLimitedError,
  StoreConflictError,
  isConvoyError,
  type ErrorCode,
  type TrustReason,
} from "./errors.js";

export type {
  AccountKeyWrapKey,
  AnchorStore,
  Argon2Cost,
  Clock,
  DeviceKeyStore,
  LocalAnchor,
  LocalDevice,
  LocalKeyStore,
  OprfPurpose,
  OprfService,
  RecordKey,
  RecordQuery,
  RecordStore,
  Settings,
  TeamStateKey,
  WireRecord,
  WriteOp,
} from "./ports.js";
