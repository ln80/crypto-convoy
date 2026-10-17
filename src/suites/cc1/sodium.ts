import libsodium from "libsodium-wrappers-sumo";

let loading: Promise<void> | undefined;
let loaded = false;

/** Loads libsodium once; every suite call needs it done. */
export function loadSodium(): Promise<void> {
  loading ??= libsodium.ready.then(() => {
    loaded = true;
  });
  return loading;
}

export function lib(): typeof libsodium {
  if (!loaded) throw new Error("crypto-convoy: libsodium isn't loaded; await ready() first");
  return libsodium;
}
