// seal.v1.json: seal with context (§3.2), wrong-context cases, low-order public keys (§2).
import { encode, fixed, hex, label, sodium, writeVectors } from "./common.mjs";

const secretKey = fixed("seal recipient", 32);
const publicKey = sodium.crypto_scalarmult_base(secretKey);
const context = [["string", "team-1"], ["string", "acct-2"], ["u32", 1], ["u32", 3]];
const body = fixed("sealed team key", 32);

const sealCase = (name, message) => ({
  name,
  message: hex(message),
  sealed: hex(sodium.crypto_box_seal(message, publicKey)),
});
const message = encode([label("grant-seal"), ...context, ["bytes", hex(body)]]);

const cases = [{
  ...sealCase("grant-seal", message),
  label: "grant-seal",
  context,
  body: hex(body),
}];

const refused = [
  { ...sealCase("trailing byte after body", new Uint8Array([...message, 0])), reason: "bytes after body" },
  { ...sealCase("other label", encode([label("submission"), ...context, ["bytes", hex(body)]])), reason: "label" },
  { ...sealCase("other team key version", encode([label("grant-seal"), ...context.slice(0, 3), ["u32", 4], ["bytes", hex(body)]])), reason: "context" },
  { ...sealCase("body length past the end", encode([label("grant-seal"), ...context, ["raw", "00000021" + hex(body)]])), reason: "body length" },
].map((c) => ({ ...c, label: "grant-seal", context, error: "DECRYPTION_FAILED" }));

// Every entry of the §2 list, and its variant with bit 255 set.
const lowOrder = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].flatMap((value) => [value, value.slice(0, 62) + (parseInt(value.slice(62), 16) | 0x80).toString(16)]);

// Independent check that each listed key yields an all-zero shared secret.
for (const value of lowOrder) {
  let refusedByLibsodium = false;
  try { sodium.crypto_scalarmult(fixed("any scalar", 32), Buffer.from(value, "hex")); } catch { refusedByLibsodium = true; }
  if (!refusedByLibsodium) throw new Error(`${value} is not low order`);
}

writeVectors("seal.v1.json", {
  file: "seal.v1",
  covers: "Protocol §3.2 seal / open, §2 low-order X25519 keys",
  recipient: { secretKey: hex(secretKey), publicKey: hex(publicKey) },
  cases,
  refused,
  lowOrderPublicKeys: lowOrder.map((publicKey) => ({ publicKey, error: "MALFORMED_RECORD" })),
});
