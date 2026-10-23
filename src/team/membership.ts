// What an owner sees and what `reconcile` may do on its own (§6.9, D-31, SP-22). Pure: no I/O, no keys.
import { hasValidRecoveryProof, type MemberKeys } from "../records/member-keys.js";
import type { Holder } from "./access.js";

/** Keys an owner reviewed: an approval holds for exactly this version (§6.8). */
export interface KeysHandle {
  readonly accountId: string;
  readonly memberKeysVersion: number;
}

/** What vouches for an account's newest keys (§6.8, §6.9): only a recovery proof acts without a human (D-38). */
export type ProofKind = "recovery" | "none";

export type AccountStatus = "no-keys" | "awaiting-approval" | "approved" | "outdated" | "rekey-awaiting-approval";

/** One account, as an owner sees it (§6.9). */
export interface AccountOverview {
  readonly accountId: string;
  readonly status: AccountStatus;
  /** The newest published keys: pass this handle to `approve`. Absent for `no-keys`. */
  readonly keys?: KeysHandle;
  /** What vouches for `keys`. Absent for `no-keys`. */
  readonly proof?: ProofKind;
  readonly isOwner: boolean;
  /** Whether the integration listed the account as active. */
  readonly active: boolean;
}

/** Something that needs an owner, with the operation that clears it (§6.9). */
export interface OwnerWarning {
  readonly code: "single-owner" | "members-awaiting-approval" | "rekeys-awaiting-approval" | "rotation-needed";
  readonly accountIds: readonly string[];
  readonly action: "setOwners" | "approve" | "reconcile";
}

export interface TeamOverview {
  readonly version: number;
  readonly owners: readonly string[];
  readonly accounts: readonly AccountOverview[];
  readonly warnings: readonly OwnerWarning[];
}

export type HumanReason = "awaiting-approval" | "outdated" | "rekey-unproven" | "owner-rekey" | "inactive-owner";

/** What `reconcile` leaves to a human, with the handle to approve if that's the answer. */
export interface NeedsHuman {
  readonly accountId: string;
  readonly reason: HumanReason;
  readonly keys?: KeysHandle;
  readonly proof?: ProofKind;
}

export interface MembershipSnapshot {
  readonly version: number;
  readonly owners: readonly string[];
  /** The calling owner: never removed. */
  readonly self: string;
  /** Holders of the current version: its roster (D-37). */
  readonly holders: readonly Holder[];
  /** Every published `member-keys` record of the team, by account, ascending versions. */
  readonly keys: ReadonlyMap<string, readonly MemberKeys[]>;
  /** Accounts without the current version that held an older one. */
  readonly heldBefore: ReadonlySet<string>;
  /** The caller's published keys versions whose bundle its session holds: only those self-approve (D-47). */
  readonly selfHeld: ReadonlySet<number>;
  readonly active: ReadonlySet<string>;
}

export interface ReconcilePlan {
  readonly rotate: boolean;
  readonly remove: readonly string[];
  readonly approveRekeys: readonly KeysHandle[];
  readonly needsHuman: readonly NeedsHuman[];
}

/** The newest keys an account holds the current version with. */
function heldKeys(snapshot: MembershipSnapshot, accountId: string): MemberKeys | undefined {
  const held = snapshot.holders.filter((h) => h.accountId === accountId).sort((a, b) => b.memberKeysVersion - a.memberKeysVersion)[0];
  return held && snapshot.keys.get(accountId)?.find((k) => k.memberKeysVersion === held.memberKeysVersion);
}

function proofOf(snapshot: MembershipSnapshot, newest: MemberKeys): ProofKind {
  const held = heldKeys(snapshot, newest.accountId);
  // Recovery proves a re-key only against the recovery key of the keys held now (§4.2).
  const proven = held && newest.memberKeysVersion > held.memberKeysVersion && hasValidRecoveryProof(newest, held.recoveryPublicKey);
  return proven ? "recovery" : "none";
}

function statusOf(snapshot: MembershipSnapshot, accountId: string, newest: MemberKeys | undefined): AccountStatus {
  if (!newest) return "no-keys";
  const held = snapshot.holders.filter((h) => h.accountId === accountId).map((h) => h.memberKeysVersion);
  if (held.includes(newest.memberKeysVersion)) return "approved";
  if (held.length > 0) return "rekey-awaiting-approval";
  return snapshot.heldBefore.has(accountId) ? "outdated" : "awaiting-approval";
}

/** Every account the integration lists or that holds the current version (§6.9). */
export function overviewOf(snapshot: MembershipSnapshot): TeamOverview {
  const ids = [...new Set([...snapshot.active, ...snapshot.holders.map((h) => h.accountId)])].sort();
  const accounts = ids.map((accountId): AccountOverview => {
    const newest = snapshot.keys.get(accountId)?.at(-1);
    const status = statusOf(snapshot, accountId, newest);
    const base = { accountId, status, isOwner: snapshot.owners.includes(accountId), active: snapshot.active.has(accountId) };
    if (!newest) return base;
    return { ...base, keys: { accountId, memberKeysVersion: newest.memberKeysVersion }, proof: proofOf(snapshot, newest) };
  });

  const warnings: OwnerWarning[] = [];
  const of = (pick: (a: AccountOverview) => boolean) => accounts.filter(pick).map((a) => a.accountId);
  if (snapshot.owners.length === 1) warnings.push({ code: "single-owner", accountIds: [...snapshot.owners], action: "setOwners" });
  const waiting = of((a) => a.active && (a.status === "awaiting-approval" || a.status === "outdated"));
  if (waiting.length > 0) warnings.push({ code: "members-awaiting-approval", accountIds: waiting, action: "approve" });
  const rekeys = of((a) => a.active && a.status === "rekey-awaiting-approval");
  if (rekeys.length > 0) warnings.push({ code: "rekeys-awaiting-approval", accountIds: rekeys, action: "approve" });
  const inactive = of((a) => !a.active && a.status !== "no-keys" && snapshot.holders.some((h) => h.accountId === a.accountId));
  if (inactive.length > 0) warnings.push({ code: "rotation-needed", accountIds: inactive, action: "reconcile" });
  return { version: snapshot.version, owners: [...snapshot.owners], accounts, warnings };
}

/**
 * What `reconcile` may do alone (§6.9, SP-22): remove inactive holders who aren't owners,
 * approve recovery-proven re-keys of members who aren't owners, and approve the caller's own
 * re-key to keys its session holds (D-47). Everything that would widen access otherwise, or add
 * or remove an owner, needs a human.
 */
export function planReconcile(snapshot: MembershipSnapshot): ReconcilePlan {
  const { accounts } = overviewOf(snapshot);
  const holding = new Set(snapshot.holders.map((h) => h.accountId));

  const remove: string[] = [];
  const approveRekeys: KeysHandle[] = [];
  const needsHuman: NeedsHuman[] = [];
  const human = (a: AccountOverview, reason: HumanReason) =>
    needsHuman.push({ accountId: a.accountId, reason, ...(a.keys ? { keys: a.keys } : {}), ...(a.proof ? { proof: a.proof } : {}) });

  for (const a of accounts) {
    if (!a.active) {
      if (!holding.has(a.accountId) || a.accountId === snapshot.self) continue;
      // Removing an owner changes the owner list: never automatic.
      if (a.isOwner) human(a, "inactive-owner");
      else remove.push(a.accountId);
      continue;
    }
    switch (a.status) {
      case "rekey-awaiting-approval":
        // An owner's re-key: only the caller's own, to keys its session holds (D-47).
        if (a.isOwner) {
          if (a.accountId === snapshot.self && snapshot.selfHeld.has(a.keys!.memberKeysVersion)) approveRekeys.push(a.keys!);
          else human(a, "owner-rekey");
        }
        else if (a.proof === "recovery") approveRekeys.push(a.keys!);
        else human(a, "rekey-unproven");
        break;
      case "awaiting-approval":
        human(a, "awaiting-approval");
        break;
      case "outdated":
        human(a, "outdated");
        break;
      default:
        break;
    }
  }
  return { rotate: remove.length > 0 || approveRekeys.length > 0, remove, approveRekeys, needsHuman };
}
