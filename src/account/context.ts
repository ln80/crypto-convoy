import type { Clock, LocalKeyStore, OprfService, RecordKey, RecordStore, ResolvedSettings, WriteOp } from "../ports.js";
import { accountKeyWrapToJson, type AccountKeyWrap } from "../records/account-key-wrap.js";
import type { Suite } from "../suites/suite.js";

/** What every account operation needs: the suite writers use, the ports and the settings. */
export interface AccountPorts {
  readonly suite: Suite;
  readonly store: RecordStore;
  readonly oprf: OprfService;
  readonly localKeys: LocalKeyStore;
  readonly clock: Clock;
  readonly settings: ResolvedSettings;
}

/** An unlocked account key. Lives in the vault only (D-03, SP-02). */
export interface OpenAccount {
  readonly accountId: string;
  readonly version: number;
  readonly key: Uint8Array;
}

export function wrapKey(wrap: Pick<AccountKeyWrap, "accountId" | "accountKeyVersion" | "method" | "deviceId">): RecordKey {
  return {
    type: "account-key-wrap",
    accountId: wrap.accountId,
    accountKeyVersion: wrap.accountKeyVersion,
    method: wrap.method,
    ...(wrap.deviceId !== undefined ? { deviceId: wrap.deviceId } : {}),
  };
}

export const createWrap = (wrap: AccountKeyWrap): WriteOp => ({ op: "create", key: wrapKey(wrap), record: accountKeyWrapToJson(wrap) });

/** Replacing a write-once wrap: delete then create, in one batch (§5.6). */
export const replaceWrap = (wrap: AccountKeyWrap): WriteOp[] => [{ op: "delete", key: wrapKey(wrap) }, createWrap(wrap)];
