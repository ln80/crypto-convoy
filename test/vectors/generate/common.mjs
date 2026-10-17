// Shared helpers for vector generators. Independent of src/ on purpose:
// a bug in the library must not be able to validate itself (testing guide).
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import libsodium from "libsodium-wrappers-sumo";

await libsodium.ready;
export const sodium = libsodium;

export const VECTORS = join(import.meta.dirname, "..");
export const hex = (bytes) => Buffer.from(bytes).toString("hex");
export const unhex = (text) => new Uint8Array(Buffer.from(text, "hex"));
export const b64u = (bytes) => Buffer.from(bytes).toString("base64url");

/** Deterministic bytes for a named value, so generated inputs are reproducible. */
export const fixed = (name, length) => sodium.crypto_generichash(length, `crypto-convoy vectors: ${name}`);

// Minimal canonical encoder (§1), written separately from src/encoding.
const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
export function field([type, value]) {
  switch (type) {
    case "u8": return Buffer.from([value]);
    case "u32": return u32be(value);
    case "u64": return u64be(value);
    case "bytes": { const v = unhex(value); return Buffer.concat([u32be(v.length), v]); }
    case "string": { const v = Buffer.from(value, "utf8"); return Buffer.concat([u32be(v.length), v]); }
    case "raw": return Buffer.from(unhex(value));
    default: throw new Error(`unknown field type ${type}`);
  }
}
export const encode = (fields) => new Uint8Array(Buffer.concat(fields.map(field)));
export const label = (name) => ["string", `crypto-convoy/v1/${name}`];

/** Released vectors never change: refuse to overwrite (protocol §13). */
export function writeVectors(file, data, attachments = {}) {
  const path = join(VECTORS, file);
  if (existsSync(path) && !process.env.VECTORS_OVERWRITE_UNRELEASED) {
    console.log(`skip ${file}: exists (frozen)`);
    return;
  }
  for (const [name, bytes] of Object.entries(attachments)) {
    const attachment = join(VECTORS, name);
    mkdirSync(dirname(attachment), { recursive: true });
    writeFileSync(attachment, bytes);
  }
  // Arrays of plain values on one line, to keep field lists readable.
  const json = JSON.stringify(data, null, 2).replace(/\[\s*([^\[\]{}]*?)\s*\]/g, (_, inner) =>
    `[${inner.split(/,\s*/).join(", ")}]`,
  );
  writeFileSync(path, json + "\n");
  console.log(`wrote ${file}`);
}
