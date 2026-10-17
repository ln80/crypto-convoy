/** Browser adapter: an IndexedDB `LocalKeyStore` and `takeLinkKey()` (D-08, D-22). */
export {
  createIndexedDbLocalKeyStore,
  type BrowserLocalKeyStore,
  type IndexedDbLocalKeyStoreOptions,
} from "./indexeddb-local-key-store.js";
export { takeLinkKey, type TakeLinkKeyOptions } from "./take-link-key.js";
