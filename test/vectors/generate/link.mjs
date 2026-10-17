// link.v1.json: link values with their version prefix (§3.5).
import { b64u, fixed, hex, sodium, writeVectors } from "./common.mjs";

const itemKey = fixed("link item key", 32);
const inboxPublicKey = sodium.crypto_scalarmult_base(fixed("link inbox secret", 32));
const anchorHash = fixed("link anchor hash", 32);
const anchorBody = Buffer.concat([Buffer.from([0, 0, 0, 7]), Buffer.from([0, 0, 0, 32]), anchorHash]);

const valid = [
  { name: "item key", kind: "key", value: "1" + b64u(itemKey), bytes: hex(itemKey) },
  { name: "inbox public key", kind: "inbox-key", value: "1" + b64u(inboxPublicKey), bytes: hex(inboxPublicKey) },
  { name: "invite anchor", kind: "anchor", value: "1" + b64u(anchorBody), version: 7, hash: hex(anchorHash) },
];

const key = b64u(itemKey);
const lastChar = key[key.length - 1];
// The last character of a 32-byte value carries 4 data bits and 2 padding bits.
const nonCanonical = key.slice(0, -1) + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(lastChar) | 1];

const refused = [
  { name: "empty", kind: "key", value: "", error: "MALFORMED_RECORD" },
  { name: "prefix 2", kind: "key", value: "2" + key, error: "UNSUPPORTED_VERSION" },
  { name: "prefix 0", kind: "key", value: "0" + key, error: "UNSUPPORTED_VERSION" },
  { name: "no prefix", kind: "key", value: key, error: key[0] === "1" ? "MALFORMED_RECORD" : "UNSUPPORTED_VERSION" },
  { name: "31 bytes", kind: "key", value: "1" + b64u(itemKey.subarray(0, 31)), error: "MALFORMED_RECORD" },
  { name: "33 bytes", kind: "key", value: "1" + b64u(Buffer.concat([itemKey, Buffer.from([0])])), error: "MALFORMED_RECORD" },
  { name: "padding", kind: "key", value: "1" + key + "=", error: "MALFORMED_RECORD" },
  { name: "standard base64 alphabet", kind: "key", value: "1" + key.replace(/-/g, "+").replace(/_/g, "/") + (key.includes("-") || key.includes("_") ? "" : "+"), error: "MALFORMED_RECORD" },
  { name: "non-canonical trailing bits", kind: "key", value: "1" + nonCanonical, error: "MALFORMED_RECORD" },
  { name: "low-order inbox key", kind: "inbox-key", value: "1" + b64u(Buffer.alloc(32)), error: "MALFORMED_RECORD" },
  { name: "low-order inbox key, top bit set", kind: "inbox-key", value: "1" + b64u(Buffer.from("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880", "hex")), error: "MALFORMED_RECORD" },
  { name: "anchor version 0", kind: "anchor", value: "1" + b64u(Buffer.concat([Buffer.alloc(4), Buffer.from([0, 0, 0, 32]), anchorHash])), error: "MALFORMED_RECORD" },
  { name: "anchor with trailing byte", kind: "anchor", value: "1" + b64u(Buffer.concat([anchorBody, Buffer.from([0])])), error: "MALFORMED_RECORD" },
  { name: "anchor hash of 31 bytes", kind: "anchor", value: "1" + b64u(Buffer.concat([Buffer.from([0, 0, 0, 7, 0, 0, 0, 31]), anchorHash.subarray(0, 31)])), error: "MALFORMED_RECORD" },
  { name: "anchor prefix 2", kind: "anchor", value: "2" + b64u(anchorBody), error: "UNSUPPORTED_VERSION" },
];

writeVectors("link.v1.json", { file: "link.v1", covers: "Protocol §3.5 link values, §2 low-order inbox keys", valid, refused });
