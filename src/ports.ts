// The four interfaces the integration provides, and the library's settings (protocol §12).
import { ConvoyError, RateLimitedError, StoreConflictError, malformed } from "./errors.js";

/** A key record's identity on the server (§11). Content never goes through the key store (D-25). */
export type RecordKey =
  | { type: "account-key-wrap"; accountId: string; accountKeyVersion: number; method: "pin" | "recovery" | "device"; deviceId?: string }
  | { type: "member-keys"; teamId: string; accountId: string; memberKeysVersion: number }
  | { type: "member-keys-wrap"; accountId: string; teamId: string; memberKeysVersion: number; accountKeyVersion: number }
  | TeamStateKey
  | { type: "team-key-version"; teamId: string; version: number }
  | { type: "grant"; teamId: string; accountId: string; memberKeysVersion: number; teamKeyVersion: number }
  | { type: "item"; teamId: string; itemId: string }
  | { type: "inbox"; teamId: string; inboxId: string }
  | { type: "invite"; teamId: string; inviteId: string };

export type TeamStateKey = { type: "team-state"; accountId: string; teamId: string };

/** What `RecordStore.list` can be asked; results come in identity order (versions ascending). */
export type RecordQuery =
  | { type: "account-key-wrap"; accountId: string; accountKeyVersion: number }
  | { type: "member-keys-wrap"; accountId: string; accountKeyVersion: number }
  | { type: "member-keys"; teamId: string; accountId?: string }
  | { type: "team-key-version"; teamId: string; fromVersion: number }
  | { type: "grant"; teamId: string; teamKeyVersion?: number; accountId?: string; memberKeysVersion?: number }
  | { type: "invite"; teamId: string };

/** A record as JSON: the library writes and parses it, the store keeps it as is. */
export type WireRecord = { readonly [key: string]: unknown };

export type WriteOp =
  | { op: "create"; key: RecordKey; record: WireRecord }
  /** `expectedRevision` is `null` when the record must not exist yet. */
  | { op: "compare-and-set"; key: TeamStateKey; expectedRevision: number | null; record: WireRecord }
  | { op: "delete"; key: RecordKey }
  /** Switches an account's current account key version; `expected` is `null` at setup. */
  | { op: "set-account-key-version"; accountId: string; expected: number | null; accountKeyVersion: number };

/**
 * The key store: fetches and publishes key records. The integration authenticates calls and
 * maps them to its API; a conforming server enforces the rules of protocol §11.
 */
export interface RecordStore {
  get(key: RecordKey): Promise<unknown>;
  list(query: RecordQuery): Promise<unknown[]>;
  getAccountKeyVersion(accountId: string): Promise<number | null>;
  /**
   * Applies every operation or none. A write refused by a server rule throws
   * `StoreConflictError`; any other failure throws anything else.
   */
  commit(ops: readonly WriteOp[]): Promise<void>;
}

export type OprfPurpose = "unlock" | "enroll";

/** The server side of PIN hardening (§5.1). Calls are never retried by the library. */
export interface OprfService {
  /** Throws `RateLimitedError` when the account's PIN budget is spent. */
  evaluate(request: {
    accountId: string;
    blindedElement: Uint8Array;
    oprfKeyId: number;
    purpose: OprfPurpose;
  }): Promise<Uint8Array>;
  currentKeyId(accountId: string): Promise<number>;
}

export interface LocalDevice {
  readonly deviceId: string;
  readonly deviceKey: Uint8Array;
}

export interface LocalAnchor {
  readonly version: number;
  readonly hash: Uint8Array;
}

/** The vault's half of device-local state (§12). A value that can't be read back must throw, never read as absent. */
export interface DeviceKeyStore {
  getDevice(accountId: string): Promise<LocalDevice | null>;
  setDevice(accountId: string, device: LocalDevice): Promise<void>;
  deleteDevice(accountId: string): Promise<void>;
  getAccountKeyVersion(accountId: string): Promise<number | null>;
  setAccountKeyVersion(accountId: string, version: number): Promise<void>;
}

/** The team sessions' half: each team's anchor (SP-07). Same rule on unreadable values. */
export interface AnchorStore {
  getAnchor(accountId: string, teamId: string): Promise<LocalAnchor | null>;
  setAnchor(accountId: string, teamId: string, anchor: LocalAnchor): Promise<void>;
  deleteAnchor(accountId: string, teamId: string): Promise<void>;
}

/** Both halves, for an integration running vault and sessions in one context. */
export type LocalKeyStore = DeviceKeyStore & AnchorStore;

/** Unix seconds, for record timestamps (§1). */
export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Math.floor(Date.now() / 1000) };

export interface Argon2Cost {
  readonly opslimit: number;
  readonly memlimit: number;
}

/** Integration settings (D-17, §3.4). */
export interface Settings {
  /** Cost of new PIN wraps (default 3 passes, 256 MiB) and the lowest cost accepted (default the same). */
  readonly argon2?: { readonly write?: Argon2Cost; readonly min?: Argon2Cost };
  /** Largest part ciphertext the buffered API accepts, in bytes (default 64 MiB). */
  readonly maxBufferedSize?: number;
}

export interface ResolvedSettings {
  readonly argon2: { readonly write: Argon2Cost; readonly min: Argon2Cost };
  readonly maxBufferedSize: number;
}

const MiB = 1024 * 1024;
// Hard floor and ceiling of §2; no setting goes past them (D-17).
const FLOOR: Argon2Cost = { opslimit: 2, memlimit: 64 * MiB };
const CEILING: Argon2Cost = { opslimit: 10, memlimit: 1024 * MiB };
const DEFAULT_COST: Argon2Cost = { opslimit: 3, memlimit: 256 * MiB };

const within = (cost: Argon2Cost, low: Argon2Cost) =>
  Number.isInteger(cost.opslimit) &&
  Number.isInteger(cost.memlimit) &&
  cost.opslimit >= low.opslimit &&
  cost.memlimit >= low.memlimit &&
  cost.opslimit <= CEILING.opslimit &&
  cost.memlimit <= CEILING.memlimit;

/** Throws `MALFORMED_RECORD` for settings below the floor or inconsistent. */
export function resolveSettings(settings: Settings = {}): ResolvedSettings {
  const write = settings.argon2?.write ?? DEFAULT_COST;
  const min = settings.argon2?.min ?? write;
  const maxBufferedSize = settings.maxBufferedSize ?? 64 * MiB;
  if (!within(min, FLOOR) || !within(write, min)) throw malformed();
  if (!Number.isSafeInteger(maxBufferedSize) || maxBufferedSize < 1) throw malformed();
  return { argon2: { write, min }, maxBufferedSize };
}

/**
 * Runs a store or OPRF call. Conflicts pass through for the caller to map; a rate limit
 * is `PIN_RATE_LIMITED`; anything else is `STORE_ERROR`.
 */
export async function callPort<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    if (error instanceof ConvoyError || error instanceof StoreConflictError) throw error;
    if (error instanceof RateLimitedError) throw new ConvoyError("PIN_RATE_LIMITED");
    throw new ConvoyError("STORE_ERROR", undefined, { cause: error });
  }
}
