/** Error codes of protocol §9. */
export type ErrorCode =
  | "MALFORMED_RECORD"
  | "UNSUPPORTED_VERSION"
  | "TRUST_FAILURE"
  | "DECRYPTION_FAILED"
  | "WRONG_CREDENTIAL"
  | "PIN_RATE_LIMITED"
  | "DEVICE_NOT_REGISTERED"
  | "NOT_GRANTED"
  | "STALE_VERSION"
  | "LAST_OWNER"
  | "NOT_AN_OWNER"
  | "RECOVERY_NOT_SET_UP"
  | "STORE_ERROR";

/** Reasons carried by a `TRUST_FAILURE` (§9). */
export type TrustReason =
  | "bad_signature"
  | "not_an_owner"
  | "chain_conflict"
  | "rollback"
  | "state_unreadable"
  | "context_mismatch"
  | "key_mismatch";

// Fixed per code: messages never carry keys, plaintext or record contents (§9).
const MESSAGES: Record<ErrorCode, string> = {
  MALFORMED_RECORD: "A record or link value has the wrong shape.",
  UNSUPPORTED_VERSION: "Unknown record version or algorithm suite.",
  TRUST_FAILURE: "A signature, owner, chain or context check failed.",
  DECRYPTION_FAILED: "Authenticated decryption failed.",
  WRONG_CREDENTIAL: "The PIN or recovery phrase is wrong.",
  PIN_RATE_LIMITED: "The server refused another PIN attempt.",
  DEVICE_NOT_REGISTERED: "This device is not registered for the account.",
  NOT_GRANTED: "No grant for the required team key version.",
  STALE_VERSION: "The write used a version that is no longer current.",
  LAST_OWNER: "The only owner can't leave the team.",
  NOT_AN_OWNER: "Only an owner of the current version can do this.",
  RECOVERY_NOT_SET_UP: "Set up the recovery phrase first.",
  STORE_ERROR: "The record store or OPRF service failed.",
};

/** The one error type thrown by every operation (D-23). Branch on `code`. */
export class ConvoyError extends Error {
  override readonly name = "ConvoyError";
  readonly code: ErrorCode;
  /** Set only for `TRUST_FAILURE`. */
  readonly reason?: TrustReason;

  constructor(code: ErrorCode, reason?: TrustReason, options?: { cause?: unknown }) {
    super(reason ? `${MESSAGES[code]} (${reason})` : MESSAGES[code], options);
    this.code = code;
    if (reason) this.reason = reason;
  }
}

/** True if `error` is a `ConvoyError`, optionally with the given code. */
export function isConvoyError(error: unknown, code?: ErrorCode): error is ConvoyError {
  return error instanceof ConvoyError && (code === undefined || error.code === code);
}

/** Thrown by a `RecordStore` when a server rule refuses a write (§12). */
export class StoreConflictError extends Error {
  override readonly name = "StoreConflictError";
}

/** Thrown by an `OprfService` when the PIN budget refuses an evaluation (§12). */
export class RateLimitedError extends Error {
  override readonly name = "RateLimitedError";
}

export const malformed = () => new ConvoyError("MALFORMED_RECORD");
export const unsupported = () => new ConvoyError("UNSUPPORTED_VERSION");
export const trustFailure = (reason: TrustReason) => new ConvoyError("TRUST_FAILURE", reason);
export const decryptionFailed = () => new ConvoyError("DECRYPTION_FAILED");
