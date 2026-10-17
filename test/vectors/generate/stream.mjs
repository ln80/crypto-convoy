// stream.v1.json: empty, one-chunk, exact-multiple and multi-chunk streams (§3.4).
// Large ciphertexts are attachments under stream.v1/, checked by their hash.
import { encode, fixed, hex, label, sodium, writeVectors } from "./common.mjs";

const CHUNK = 4 * 1024 * 1024;
const key = fixed("stream key", 32);
const context = [["string", "team-1"], ["string", "item-1"], ["u32", 0]];
const ad = encode([label("item-part"), ...context]);

/** Plaintext of a case: byte i is i mod 251. */
const pattern = (length) => Uint8Array.from({ length }, (_, i) => i % 251);

function encrypt(plaintext) {
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const parts = [header];
  const count = Math.max(1, Math.ceil(plaintext.length / CHUNK));
  for (let i = 0; i < count; i++) {
    const tag = i === count - 1
      ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    parts.push(sodium.crypto_secretstream_xchacha20poly1305_push(state, plaintext.subarray(i * CHUNK, (i + 1) * CHUNK), ad, tag));
  }
  return new Uint8Array(Buffer.concat(parts));
}

const attachments = {};
const lengths = { empty: 0, "one chunk": 1000, "exact multiple": CHUNK, "multi chunk": CHUNK + 1000 };
const cases = Object.entries(lengths).map(([name, length]) => {
  const ciphertext = encrypt(pattern(length));
  const out = {
    name,
    plaintextLength: length,
    plaintextHash: hex(sodium.crypto_generichash(32, pattern(length))),
    ciphertextLength: ciphertext.length,
    ciphertextHash: hex(sodium.crypto_generichash(32, ciphertext)),
  };
  if (ciphertext.length <= 4096) return { ...out, ciphertext: hex(ciphertext) };
  const file = `stream.v1/${name.replace(/ /g, "-")}.bin`;
  attachments[file] = ciphertext;
  return { ...out, ciphertextFile: file };
});

writeVectors("stream.v1.json", {
  file: "stream.v1",
  covers: "Protocol §3.4 stream",
  plaintextPattern: "byte i = i mod 251",
  chunkSize: CHUNK,
  key: hex(key),
  label: "item-part",
  context,
  ad: hex(ad),
  cases,
}, attachments);
