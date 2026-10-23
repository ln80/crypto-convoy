// wrap.v1.json: wrap with each label (§3.1, §4), plus tampering cases.
import { encode, fixed, hex, label, optionalOf, sodium, writeVectors } from "./common.mjs";

const key32 = (name) => hex(fixed(name, 32));
const contexts = {
  "account-key-wrap": [["string", "acct-1"], ["u32", 1], ["string", "pin"], ["optional", null],
    ["bytes", hex(fixed("salt", 16))], ["u64", 3], ["u64", 268435456], ["u32", 1]],
  "member-keys-wrap": [["string", "acct-1"], ["string", "team-1"], ["u32", 1], ["u32", 1]],
  "team-state": [["string", "acct-1"], ["string", "team-1"], ["u64", 1]],
  "team-key-link": [["string", "team-1"], ["u32", 2]],
  "item-key": [["string", "team-1"], ["string", "item-1"], ["u32", 1], ["string", "acct-1"],
    ["u64", 1700000000], ["bytes", hex(fixed("manifest hash", 32))]],
  "item-manifest": [["string", "team-1"], ["string", "item-1"]],
  "inbox-key": [["string", "team-1"], ["string", "inbox-1"], ["u32", 1], ["bytes", hex(fixed("inbox pk", 32))],
    ["string", "acct-1"], ["u64", 1700000000]],
};

// The optional field is encoded by the generator's own rules (§1): 0 absent, 1 + value present.
const flat = (fields) => fields.map((f) => (f[0] === "optional" ? (f[1] === null ? ["u8", 0] : ["raw", "01" + hex(encode([f[1]]))]) : f));

const cases = Object.entries(contexts).map(([name, context]) => {
  const key = fixed(`wrap key ${name}`, 32);
  const nonce = fixed(`wrap nonce ${name}`, 24);
  const plaintext = fixed(`wrap plaintext ${name}`, 32);
  const ad = encode([label(name), ...flat(context)]);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key);
  return {
    name: `wrap ${name}`,
    label: name,
    context,
    inputs: { key: hex(key), nonce: hex(nonce), plaintext: hex(plaintext) },
    intermediate: { ad: hex(ad) },
    outputs: { ciphertext: hex(ciphertext) },
  };
});

const base = cases[0];
const flip = (text, index) => {
  const bytes = Buffer.from(text, "hex");
  bytes[index] ^= 0x01;
  return bytes.toString("hex");
};
const tampered = [
  { name: "ciphertext bit flipped", from: base.name, ciphertext: flip(base.outputs.ciphertext, 0) },
  { name: "tag bit flipped", from: base.name, ciphertext: flip(base.outputs.ciphertext, base.outputs.ciphertext.length / 2 - 1) },
  { name: "nonce bit flipped", from: base.name, nonce: flip(base.inputs.nonce, 3) },
  { name: "wrong key", from: base.name, key: key32("another key") },
  { name: "other context: account key version 2", from: base.name, context: base.context.map((f, i) => (i === 1 ? ["u32", 2] : f)) },
  { name: "other label", from: base.name, label: "member-keys-wrap" },
  { name: "truncated to 15 bytes", from: base.name, ciphertext: base.outputs.ciphertext.slice(0, 30) },
  { name: "nonce of 23 bytes", from: base.name, nonce: base.inputs.nonce.slice(0, 46) },
].map((c) => ({ ...c, error: "DECRYPTION_FAILED" }));

// Member keys bundles (§4.3): seed ‖ secret key ‖ team state key ‖ optional anchor floor (D-48).
const bundleContext = contexts["member-keys-wrap"];
const bundleKey = fixed("bundle account key", 32);
const bundleParts = {
  signingSeed: hex(fixed("bundle signing seed", 32)),
  encryptionSecretKey: hex(fixed("bundle encryption secret", 32)),
  teamStateKey: hex(fixed("bundle team state key", 32)),
};
const bundleFloor = { version: 4, hash: hex(fixed("bundle floor hash", 32)) };
const sealBundle = (name, plaintext) => {
  const nonce = fixed(`bundle nonce ${name}`, 24);
  const ad = encode([label("member-keys-wrap"), ...bundleContext]);
  return { nonce: hex(nonce), ciphertext: hex(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, bundleKey)) };
};
const bundlePlaintext = (floorFields) =>
  encode([["raw", bundleParts.signingSeed], ["raw", bundleParts.encryptionSecretKey], ["raw", bundleParts.teamStateKey], optionalOf(floorFields)]);
const bundles = {
  key: hex(bundleKey),
  context: bundleContext,
  cases: [
    { name: "bundle without a floor", ...bundleParts, plaintext: hex(bundlePlaintext(null)) },
    { name: "bundle with a floor", ...bundleParts, floor: bundleFloor, plaintext: hex(bundlePlaintext([["u32", bundleFloor.version], ["bytes", bundleFloor.hash]])) },
  ].map((c) => ({ ...c, wrapped: sealBundle(c.name, Buffer.from(c.plaintext, "hex")) })),
  refused: [
    { name: "96 bytes, no floor flag", plaintext: bundleParts.signingSeed + bundleParts.encryptionSecretKey + bundleParts.teamStateKey },
    { name: "floor hash of 31 bytes", plaintext: hex(bundlePlaintext([["u32", 4], ["bytes", bundleFloor.hash.slice(0, 62)]])) },
    { name: "trailing byte after the floor flag", plaintext: hex(bundlePlaintext(null)) + "00" },
  ].map((c) => ({ ...c, wrapped: sealBundle(c.name, Buffer.from(c.plaintext, "hex")), error: "DECRYPTION_FAILED" })),
};

writeVectors("wrap.v1.json", { file: "wrap.v1", covers: "Protocol §3.1 wrap / unwrap, §4.3 member keys bundles", cases, tampered, bundles });
