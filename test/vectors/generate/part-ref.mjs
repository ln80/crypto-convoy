// part-ref.v1.json: part reference key and references (§3.9).
import { b64u, encode, fixed, hex, label, sodium, writeVectors } from "./common.mjs";

const pattern = (length) => Uint8Array.from({ length }, (_, i) => i % 251);
const cases = [
  { name: "item key, short text", key: fixed("part-ref item key", 32), content: new TextEncoder().encode("hello, team") },
  { name: "item key, empty content", key: fixed("part-ref item key", 32), content: new Uint8Array(0) },
  { name: "submission content key, 5 MiB", key: fixed("part-ref content key", 32), content: pattern(5 * 1024 * 1024) },
].map(({ name, key, content }) => {
  const refKey = sodium.crypto_generichash(32, encode([label("part-ref")]), key);
  const ref = b64u(sodium.crypto_generichash(32, content, refKey));
  return {
    name,
    contentKey: hex(key),
    content: content.length <= 64 ? hex(content) : { pattern: "byte i = i mod 251", length: content.length },
    refKey: hex(refKey),
    partRef: ref,
  };
});

writeVectors("part-ref.v1.json", { file: "part-ref.v1", covers: "Protocol §3.9 part references", cases });
