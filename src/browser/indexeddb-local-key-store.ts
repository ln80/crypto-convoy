// LocalKeyStore over IndexedDB, encrypted under a non-extractable WebCrypto key (§3.7, D-08).
import { Reader, bytes, enc, string, u32 } from "../encoding/canonical.js";
import { labelled, type Label } from "../encoding/labels.js";
import { ConvoyError } from "../errors.js";
import type { LocalAnchor, LocalDevice, LocalKeyStore } from "../ports.js";
import { CURRENT_SUITE, ready } from "../suites/registry.js";

export interface IndexedDbLocalKeyStoreOptions {
  /** Defaults to the global `indexedDB` (window or worker). */
  readonly indexedDB?: IDBFactory;
  /** Defaults to the global `crypto.subtle`. */
  readonly subtle?: SubtleCrypto;
  readonly dbName?: string;
}

const KEYS = "keys";
const VALUES = "values";
const WRAPPING_KEY = "local-wrapping-key";
const IV = 12;

// WebCrypto's types want ArrayBuffer-backed views; ours always are.
const view = (value: Uint8Array) => value as Uint8Array<ArrayBuffer>;

/** A `LocalKeyStore` for browsers, plus `clear` for sign-out. */
export interface BrowserLocalKeyStore extends LocalKeyStore {
  /** Removes this device's key and anchors for an account. */
  clear(accountId: string): Promise<void>;
}

const request = <T>(req: IDBRequest<T>) =>
  new Promise<T>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

const done = (tx: IDBTransaction) =>
  new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });

/** Opens (or creates) the store. Loads libsodium for the IVs (§3.6). */
export async function createIndexedDbLocalKeyStore(options: IndexedDbLocalKeyStoreOptions = {}): Promise<BrowserLocalKeyStore> {
  await ready();
  const factory = options.indexedDB ?? globalThis.indexedDB;
  const subtle = options.subtle ?? globalThis.crypto.subtle;
  const open = factory.open(options.dbName ?? "crypto-convoy", 1);
  open.onupgradeneeded = () => {
    open.result.createObjectStore(KEYS);
    open.result.createObjectStore(VALUES);
  };
  const db = await request(open);
  const wrappingKey = await localWrappingKey(db, subtle);

  async function put(id: string, name: Label, context: string[], plaintext: Uint8Array) {
    const iv = CURRENT_SUITE.randomBytes(IV);
    const ad = labelled(name, ...context.map(string));
    const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: view(iv), additionalData: view(ad) }, wrappingKey, view(plaintext)));
    CURRENT_SUITE.wipe(plaintext);
    const tx = db.transaction(VALUES, "readwrite");
    tx.objectStore(VALUES).put(enc(bytes(iv), bytes(ciphertext)), id);
    await done(tx);
  }

  async function get(id: string, name: Label, context: string[]): Promise<Reader | null> {
    const stored = await request(db.transaction(VALUES).objectStore(VALUES).get(id));
    if (stored === undefined) return null;
    try {
      const outer = new Reader(stored as Uint8Array);
      const iv = outer.bytes();
      const ciphertext = outer.bytes();
      outer.end();
      const ad = labelled(name, ...context.map(string));
      return new Reader(new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: view(iv), additionalData: view(ad) }, wrappingKey, view(ciphertext))));
    } catch {
      // Never read as absent: a lost anchor would mean first-contact trust again (SP-07).
      throw new ConvoyError("DECRYPTION_FAILED");
    }
  }

  async function remove(...ids: string[]) {
    const tx = db.transaction(VALUES, "readwrite");
    for (const id of ids) tx.objectStore(VALUES).delete(id);
    await done(tx);
  }

  const deviceId = (accountId: string) => `device\0${accountId}`;
  const versionId = (accountId: string) => `account-version\0${accountId}`;
  const anchorId = (accountId: string, teamId: string) => `anchor\0${accountId}\0${teamId}`;
  const vaultAnchorId = (accountId: string, teamId: string) => `vault-anchor\0${accountId}\0${teamId}`;

  return {
    async getDevice(accountId): Promise<LocalDevice | null> {
      const reader = await get(deviceId(accountId), "local-device-key", [accountId]);
      if (!reader) return null;
      const device = { deviceId: reader.string(), deviceKey: reader.bytes() };
      reader.end();
      return device;
    },
    setDevice: (accountId, device) =>
      put(deviceId(accountId), "local-device-key", [accountId], enc(string(device.deviceId), bytes(device.deviceKey))),
    deleteDevice: (accountId) => remove(deviceId(accountId)),

    async getAccountKeyVersion(accountId) {
      const reader = await get(versionId(accountId), "local-account-version", [accountId]);
      if (!reader) return null;
      const version = reader.u32();
      reader.end();
      return version;
    },
    setAccountKeyVersion: (accountId, version) => put(versionId(accountId), "local-account-version", [accountId], u32(version)),

    async getAnchor(accountId, teamId): Promise<LocalAnchor | null> {
      const reader = await get(anchorId(accountId, teamId), "local-anchor", [accountId, teamId]);
      if (!reader) return null;
      const anchor = { version: reader.u32(), hash: reader.bytes() };
      reader.end();
      return anchor;
    },
    setAnchor: (accountId, teamId, anchor) =>
      put(anchorId(accountId, teamId), "local-anchor", [accountId, teamId], enc(u32(anchor.version), bytes(anchor.hash))),
    deleteAnchor: (accountId, teamId) => remove(anchorId(accountId, teamId)),

    async getVaultAnchor(accountId, teamId): Promise<LocalAnchor | null> {
      const reader = await get(vaultAnchorId(accountId, teamId), "local-vault-anchor", [accountId, teamId]);
      if (!reader) return null;
      const anchor = { version: reader.u32(), hash: reader.bytes() };
      reader.end();
      return anchor;
    },
    setVaultAnchor: (accountId, teamId, anchor) =>
      put(vaultAnchorId(accountId, teamId), "local-vault-anchor", [accountId, teamId], enc(u32(anchor.version), bytes(anchor.hash))),
    deleteVaultAnchor: (accountId, teamId) => remove(vaultAnchorId(accountId, teamId)),

    async clear(accountId) {
      const keys = (await request(db.transaction(VALUES).objectStore(VALUES).getAllKeys())) as string[];
      await remove(...keys.filter((k) => k.split("\0")[1] === accountId));
    },
  };
}

/** Generated once per browser profile; the first writer wins when two tabs race. */
async function localWrappingKey(db: IDBDatabase, subtle: SubtleCrypto): Promise<CryptoKey> {
  const existing = await request(db.transaction(KEYS).objectStore(KEYS).get(WRAPPING_KEY));
  if (existing) return existing as CryptoKey;
  const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const tx = db.transaction(KEYS, "readwrite");
  tx.objectStore(KEYS).add(key, WRAPPING_KEY);
  try {
    await done(tx);
    return key;
  } catch {
    return (await request(db.transaction(KEYS).objectStore(KEYS).get(WRAPPING_KEY))) as CryptoKey;
  }
}
