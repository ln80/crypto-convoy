// A small world for scenario tests: one honest server, one OPRF server, devices per account.
import { createVault, type Vault } from "../../src/account/vault.js";
import type { OprfService, Settings } from "../../src/ports.js";
import { FakeOprfServer, MemoryLocalKeyStore, MemoryRecordStore, fixedClock } from "../../src/testing/index.js";
import { TamperingStore } from "./fake-store.js";

const MiB = 1024 * 1024;
/** The cheapest Argon2id the library allows (§2 floor), to keep tests fast. */
export const FAST: Settings = { argon2: { write: { opslimit: 2, memlimit: 64 * MiB }, min: { opslimit: 2, memlimit: 64 * MiB } } };

export interface Device {
  readonly vault: Vault;
  readonly store: TamperingStore;
  readonly localKeys: MemoryLocalKeyStore;
}

export function world(options: { budget?: number } = {}) {
  const server = new MemoryRecordStore();
  const oprf = new FakeOprfServer({ budget: options.budget ?? 100 });
  const clock = fixedClock();

  /** A new device (browser profile) for `accountId`, talking to the server through tamper hooks. */
  async function device(
    accountId: string,
    extra: { settings?: Settings; oprf?: OprfService; localKeys?: MemoryLocalKeyStore } = {},
  ): Promise<Device> {
    const store = new TamperingStore(server.as(accountId));
    const localKeys = extra.localKeys ?? new MemoryLocalKeyStore();
    const vault = await createVault({ store, oprf: extra.oprf ?? oprf, localKeys, clock, settings: extra.settings ?? FAST }, accountId);
    return { vault, store, localKeys };
  }

  /** An account set up on its first device; returns the device and the recovery phrase. */
  async function account(accountId: string, pin = "1234") {
    const first = await device(accountId);
    const { recoveryPhrase } = await first.vault.setup(pin);
    return { ...first, recoveryPhrase, pin };
  }

  return { server, oprf, clock, device, account };
}
