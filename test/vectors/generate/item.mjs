// item.v1.json: item record, manifest and parts (§4.7, §4.8), with swap and tamper cases.
import { b64u, blake, encode, fixed, hex, label, listOf, sodium, wrapWith, wrappedHashOf, wrappedJson, writeVectors } from "./common.mjs";

const TEAM = "team-1";
const ITEM = "item-1";
const teamKey = fixed("item team key", 32);
const itemKey = fixed("item key", 32);
const createdAt = 1_700_000_500;

function streamOf(plaintext, context) {
  const ad = encode([label("item-part"), ...context]);
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(itemKey);
  const chunk = sodium.crypto_secretstream_xchacha20poly1305_push(state, plaintext, ad, sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL);
  return new Uint8Array(Buffer.concat([header, chunk]));
}

const contents = [
  { content: new TextEncoder().encode("hello, team"), meta: new TextEncoder().encode('{"kind":"text"}') },
  { content: fixed("file bytes", 64), meta: new Uint8Array(0) },
];
const parts = contents.map((p, index) => streamOf(p.content, [["string", TEAM], ["string", ITEM], ["u32", index]]));
const manifest = encode([listOf(parts.map((ct, index) => [
  ["u32", index], ["u64", ct.length], ["bytes", hex(blake(ct))], ["bytes", hex(contents[index].meta)],
]))]);

const wrappedManifest = wrapWith(itemKey, fixed("manifest nonce", 24), "item-manifest", [["string", TEAM], ["string", ITEM]], manifest);
const wrappedItemKey = wrapWith(teamKey, fixed("item key nonce", 24), "item-key", [
  ["string", TEAM], ["string", ITEM], ["u32", 1], ["string", "alice"], ["u64", createdAt], ["bytes", hex(wrappedHashOf(wrappedManifest))],
], itemKey);

const record = {
  v: 1, suite: "cc1", type: "item", teamId: TEAM, itemId: ITEM, teamKeyVersion: 1, createdBy: "alice", createdAt,
  wrappedManifest: wrappedJson(wrappedManifest), wrappedItemKey: wrappedJson(wrappedItemKey),
};

// A second item of the same team, to swap parts and manifests across items.
const otherManifest = wrapWith(itemKey, fixed("manifest nonce 2", 24), "item-manifest", [["string", TEAM], ["string", "item-2"]], manifest);

writeVectors("item.v1.json", {
  file: "item.v1",
  covers: "Protocol §4.7 item, §4.8 parts, D-16 manifest",
  teamKey: hex(teamKey),
  itemKey: hex(itemKey),
  record,
  manifest: hex(manifest),
  parts: parts.map((ct, i) => ({ ciphertext: hex(ct), plaintext: hex(contents[i].content), meta: hex(contents[i].meta) })),
  tampered: [
    { name: "createdBy changed", record: { ...record, createdBy: "mallory" }, error: "DECRYPTION_FAILED" },
    { name: "teamKeyVersion changed", record: { ...record, teamKeyVersion: 2 }, error: "DECRYPTION_FAILED" },
    { name: "manifest of another item", record: { ...record, wrappedManifest: wrappedJson(otherManifest) }, error: "DECRYPTION_FAILED" },
    { name: "record of another item id", record: { ...record, itemId: "item-2" }, expectedItemId: "item-1", error: "TRUST_FAILURE", reason: "context_mismatch" },
  ],
  swappedParts: [
    { name: "parts swapped", order: [1, 0], error: "DECRYPTION_FAILED" },
    { name: "part dropped", order: [0], error: "DECRYPTION_FAILED" },
  ],
});
