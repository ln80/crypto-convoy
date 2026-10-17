// Reading a link value from the URL fragment and removing it at once (§3.5, D-22).
import { decodeLinkKey } from "../encoding/link.js";

export interface TakeLinkKeyOptions {
  /** Defaults to `window.location`. */
  readonly location?: Pick<Location, "hash" | "href">;
  /** Defaults to `window.history`. */
  readonly history?: Pick<History, "replaceState" | "state">;
}

/**
 * Takes the key from the fragment and removes the fragment from the address bar and history,
 * even when the value is invalid. Returns it for `openSharedItem` or `submitToInbox`.
 * Throws `MALFORMED_RECORD` or `UNSUPPORTED_VERSION`; returns `null` when there is no fragment.
 */
export function takeLinkKey(options: TakeLinkKeyOptions = {}): string | null {
  const location = options.location ?? globalThis.location;
  const history = options.history ?? globalThis.history;
  const value = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
  if (value === "") return null;
  history.replaceState(history.state, "", location.href.split("#")[0]);
  decodeLinkKey(value);
  return value;
}
